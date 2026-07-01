// Package tunnel orchestrates the full VPN connection lifecycle.
package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/auth"
	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
	vpnio "github.com/elizandrodantas/openfortivpn-go/internal/io"
	"github.com/elizandrodantas/openfortivpn-go/internal/ipv4"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp"
	"github.com/elizandrodantas/openfortivpn-go/internal/tlsconn"
	"github.com/elizandrodantas/openfortivpn-go/internal/xmlparse"
)

// TunnelState represents the VPN connection lifecycle state.
type TunnelState int32

const (
	StateDown         TunnelState = iota
	StateConnecting
	StateUp
	StateDisconnecting
)

// Tunnel manages a single VPN session.
type Tunnel struct {
	cfg    *config.Config
	state  atomic.Int32
	routes ipv4.RouteManager
	dns    ipv4.DNSManager

	// Connection objects (reset on each connect attempt)
	tlsConn   interface{ Close() error }
	httpClient *httptunnel.Client
	pppdProc  *ppp.Process
	ipv4Cfg   ipv4.Config

	// Saved default route for restoration on disconnect
	savedDefault *ipv4.Route
}

// Run establishes (and optionally reconnects) the VPN tunnel. It blocks until
// the context is cancelled or a fatal error occurs.
func Run(ctx context.Context, cfg *config.Config) error {
	t := &Tunnel{
		cfg:    cfg,
		routes: ipv4.NewRouteManager(),
		dns:    ipv4.NewDNSManager(cfg.UseResolvconf),
	}
	t.state.Store(int32(StateDown))

	for attempt := 0; ; attempt++ {
		err := t.connect(ctx)
		if err == nil {
			return nil
		}
		if cfg.Persistent == 0 {
			return err
		}
		slog.Warn("tunnel disconnected, reconnecting",
			"attempt", attempt+1,
			"error", err,
			"delay", cfg.Persistent)
		select {
		case <-time.After(cfg.Persistent):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *Tunnel) connect(ctx context.Context) error {
	t.setState(StateConnecting)
	cfg := t.cfg

	// Step 0: DNS resolve gateway host
	slog.Info("Resolving gateway", "host", cfg.GatewayHost)
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, cfg.GatewayHost)
	if err != nil {
		return fmt.Errorf("DNS resolve %s: %w", cfg.GatewayHost, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("no addresses for %s", cfg.GatewayHost)
	}
	cfg.GatewayIP = addrs[0].IP
	slog.Debug("Gateway resolved", "ip", cfg.GatewayIP)

	// Step 1: TLS connect for authentication
	slog.Info("Connecting to gateway", "host", cfg.GatewayHost, "port", cfg.GatewayPort)
	conn, rawConn, err := tlsconn.Dial(ctx, cfg)
	if err != nil {
		return fmt.Errorf("TLS connect: %w", err)
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
		if rawConn != nil {
			rawConn.Close()
		}
	}()
	t.tlsConn = conn

	// Step 2: Authenticate
	slog.Info("Authenticating", "user", cfg.Username)
	httpCli := httptunnel.NewClient(conn, fmt.Sprintf("%s:%d", cfg.GatewayHost, cfg.GatewayPort), cfg.UserAgent)
	t.httpClient = httpCli

	authenticator := auth.New(cfg)
	cookie, err := authenticator.Authenticate(ctx, httpCli, cfg)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	slog.Info("Authentication successful")
	httpCli.SetCookie(cookie)

	// Step 3: VPN allocation
	if err := t.requestVPNAllocation(ctx, httpCli); err != nil {
		return fmt.Errorf("VPN allocation: %w", err)
	}

	// Step 4: Fresh TLS connection for tunnel phase
	conn.Close()
	rawConn.Close()
	conn, rawConn, err = tlsconn.Dial(ctx, cfg)
	if err != nil {
		conn = nil
		rawConn = nil
		return fmt.Errorf("TLS reconnect: %w", err)
	}
	t.tlsConn = conn
	httpCli = httptunnel.NewClient(conn, fmt.Sprintf("%s:%d", cfg.GatewayHost, cfg.GatewayPort), cfg.UserAgent)
	httpCli.SetCookie(cookie)

	// Step 5: Fetch XML config → IP, DNS, routes
	if err := t.fetchConfig(ctx, httpCli); err != nil {
		return fmt.Errorf("config fetch: %w", err)
	}

	// Step 6: Launch pppd
	slog.Info("Launching PPP daemon")
	proc, err := ppp.Start(cfg)
	if err != nil {
		return fmt.Errorf("pppd: %w", err)
	}
	t.pppdProc = proc
	defer func() {
		if t.pppdProc != nil {
			t.pppdProc.Close()
			t.pppdProc = nil
		}
	}()

	// Step 7: Activate tunnel (upgrade connection to PPP carrier)
	slog.Info("Activating VPN tunnel")
	tunnelReq := fmt.Sprintf(
		"GET /remote/sslvpn-tunnel HTTP/1.1\r\nHost: %s:%d\r\nCookie: SVPNCOOKIE=%s\r\nUser-Agent: %s\r\n\r\n",
		cfg.GatewayHost, cfg.GatewayPort, cookie, cfg.UserAgent,
	)
	if err := httpCli.SendRaw(tunnelReq); err != nil {
		return fmt.Errorf("tunnel activate: %w", err)
	}

	// Step 8: Run I/O loop.
	// onIPCPComplete must be called at most once regardless of how it's
	// triggered (IPCP packet detection or interface polling fallback).
	var ipcpOnce sync.Once
	ipcpCallback := func(info vpnio.IPCPInfo) {
		ipcpOnce.Do(func() { t.onIPCPComplete(info) })
	}

	slog.Info("VPN tunnel active, relaying PPP packets")
	ioCfg := &vpnio.LoopConfig{
		TLSConn:  conn,
		PTY:      proc.PTY(),
		OnIPCP:   ipcpCallback,
		OnCancel: proc.Close, // kills pppd → PTY EOF → unblocks ptyReader on Ctrl+C
	}

	// Fallback: poll for the PPP interface using the XML-assigned IP in case
	// IPCP packet detection misses the event (e.g. FF 03 prefix variance,
	// or the ACK arrives before the relay loop starts inspecting).
	go func() {
		if t.ipv4Cfg.AssignedIP == nil {
			return
		}
		iface, err := findIfaceByIP(t.ipv4Cfg.AssignedIP)
		if err != nil {
			slog.Debug("interface polling timeout", "err", err)
			return
		}
		slog.Debug("PPP interface found via polling", "iface", iface)
		ipcpCallback(vpnio.IPCPInfo{
			AssignedIP: t.ipv4Cfg.AssignedIP,
			NS1:        t.ipv4Cfg.NS1,
			NS2:        t.ipv4Cfg.NS2,
		})
	}()

	if err := vpnio.RunLoop(ctx, ioCfg); err != nil {
		slog.Debug("I/O loop ended", "err", err)
	}

	// Cleanup network config
	t.setState(StateDisconnecting)
	t.teardownNetwork()
	t.setState(StateDown)
	return err
}

// requestVPNAllocation performs the HTTP steps needed to reserve a VPN session.
func (t *Tunnel) requestVPNAllocation(_ context.Context, c *httptunnel.Client) error {
	resp, err := c.Get("/remote/index")
	if err != nil {
		return fmt.Errorf("GET /remote/index: %w", err)
	}
	slog.Debug("VPN index", "status", resp.StatusCode)

	resp, err = c.Get("/remote/fortisslvpn")
	if err != nil {
		return fmt.Errorf("GET /remote/fortisslvpn: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("VPN allocation returned %d", resp.StatusCode)
	}
	return nil
}

// fetchConfig retrieves the XML VPN configuration from the gateway.
func (t *Tunnel) fetchConfig(_ context.Context, c *httptunnel.Client) error {
	resp, err := c.Get("/remote/fortisslvpn_xml")
	if err != nil {
		return fmt.Errorf("GET /remote/fortisslvpn_xml: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("config fetch returned %d", resp.StatusCode)
	}

	body := string(resp.Body)
	slog.Debug("VPN XML config received", "bytes", len(body), "body", body)

	return t.parseXMLConfig(body)
}

// parseXMLConfig extracts IP, DNS and split routes from the FortiGate XML
// response. The logic mirrors the C parse_xml_config() in http.c exactly:
//   - assigned-addr uses the "ipv4=" attribute
//   - dns elements carry "ip=" (servers) or "domain=" (suffix)
//   - split-tunnel-info/addr elements carry "ip=" and "mask="
// Needles must NOT include the quote character — xmlparse.Get() uses the
// first byte of the returned buffer as the quote (single or double).
func (t *Tunnel) parseXMLConfig(body string) error {
	// Assigned tunnel IP
	addrNode := xmlparse.Find('<', "assigned-addr", body, 1)
	ipStr, err := xmlparse.Get(xmlparse.Find(' ', "ipv4=", addrNode, 1))
	if err != nil {
		return fmt.Errorf("parse assigned IP: %w", err)
	}
	t.ipv4Cfg.AssignedIP = net.ParseIP(ipStr)
	gatewayIP := ipStr // used for split-route gateway below

	// DNS search suffix — iterate <dns> nodes until one has domain=
	for rest := body; ; {
		node := xmlparse.Find('<', "dns", rest, 2)
		if node == "" {
			break
		}
		if suffix, err := xmlparse.Get(xmlparse.Find(' ', "domain=", node, 1)); err == nil {
			t.ipv4Cfg.DNSSuffix = suffix
			break
		}
		rest = node
	}

	// DNS name servers — iterate <dns> nodes collecting ip= values
	for rest := body; ; {
		node := xmlparse.Find('<', "dns", rest, 2)
		if node == "" {
			break
		}
		if ns, err := xmlparse.Get(xmlparse.Find(' ', "ip=", node, 1)); err == nil {
			if t.ipv4Cfg.NS1 == nil {
				t.ipv4Cfg.NS1 = net.ParseIP(ns)
			} else if t.ipv4Cfg.NS2 == nil {
				t.ipv4Cfg.NS2 = net.ParseIP(ns)
			}
		}
		rest = node
	}

	// Split-tunnel routes
	splitNode := xmlparse.Find('<', "split-tunnel-info", body, 1)
	for rest := splitNode; ; {
		addrN := xmlparse.Find('<', "addr", rest, 2)
		if addrN == "" {
			break
		}
		dest, err1 := xmlparse.Get(xmlparse.Find(' ', "ip=", addrN, 1))
		mask, err2 := xmlparse.Get(xmlparse.Find(' ', "mask=", addrN, 1))
		if err1 == nil && err2 == nil {
			_, ipNet, parseErr := net.ParseCIDR(dest + "/" + maskToCIDR(mask))
			if parseErr == nil {
				t.ipv4Cfg.SplitRoutes = append(t.ipv4Cfg.SplitRoutes, *ipNet)
			}
			_ = gatewayIP // gateway used by C for nexthop; we resolve via PPP iface
		}
		rest = addrN
	}

	slog.Info("VPN config received",
		"assigned_ip", t.ipv4Cfg.AssignedIP,
		"dns1", t.ipv4Cfg.NS1,
		"dns2", t.ipv4Cfg.NS2,
		"search", t.ipv4Cfg.DNSSuffix,
		"split_routes", len(t.ipv4Cfg.SplitRoutes),
	)
	return nil
}

// maskToCIDR converts a dotted-decimal subnet mask (e.g. "255.255.255.0")
// to a CIDR prefix length string (e.g. "24").
func maskToCIDR(mask string) string {
	ip := net.ParseIP(mask)
	if ip == nil {
		return "32"
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "32"
	}
	ones, _ := net.IPMask(ip4).Size()
	return fmt.Sprintf("%d", ones)
}

// onIPCPComplete is called by the I/O loop when IPCP negotiation completes.
// It sets up routing and DNS on the system.
func (t *Tunnel) onIPCPComplete(info vpnio.IPCPInfo) {
	slog.Info("IPCP negotiation complete, configuring network",
		"ip", info.AssignedIP, "ns1", info.NS1, "ns2", info.NS2)

	cfg := t.cfg

	// Find the PPP interface by assigned IP
	iface, err := findIfaceByIP(info.AssignedIP)
	if err != nil {
		slog.Warn("could not find PPP interface", "ip", info.AssignedIP, "err", err)
		return
	}
	slog.Info("PPP interface found", "iface", iface)

	// Save original default route for restoration
	defRoute, err := t.routes.GetDefault()
	if err != nil {
		slog.Warn("could not get default route", "err", err)
	} else {
		t.savedDefault = defRoute
	}

	if cfg.SetRoutes {
		t.setupRoutes(iface, defRoute)
	}

	ns1, ns2 := info.NS1, info.NS2
	if t.ipv4Cfg.NS1 != nil {
		ns1 = t.ipv4Cfg.NS1
	}
	if t.ipv4Cfg.NS2 != nil {
		ns2 = t.ipv4Cfg.NS2
	}

	// On macOS, Apple's own pppd (see internal/ppp/pppd_unix.go) publishes
	// DNS natively via "usepeerdns"+"serviceid" whenever the FortiGate sent
	// DNS options during IPCP negotiation (info.NS1/NS2). ipcpHasDNS tells
	// darwinDNS.Add whether that already happened, so it only falls back to
	// its own /etc/resolver-based mechanism when the peer didn't provide
	// DNS via IPCP (e.g. a different FortiGate config). Other platforms
	// ignore this flag and always run their existing DNS logic.
	ipcpHasDNS := info.NS1 != nil || info.NS2 != nil

	if cfg.SetDNS && (ns1 != nil || ns2 != nil) {
		if err := t.dns.Add(iface, info.AssignedIP, ns1, ns2, t.ipv4Cfg.DNSSuffix, ipcpHasDNS); err != nil {
			slog.Warn("failed to set DNS", "err", err)
		} else {
			slog.Info("DNS configured", "ns1", ns1, "ns2", ns2, "via_ipcp", ipcpHasDNS)
		}
	}

	t.setState(StateUp)
	slog.Info("VPN tunnel is UP")
}

// setupRoutes adds the necessary routes to direct traffic through the VPN.
// Mirrors C's ipv4_set_tunnel_routes logic:
//   - Split routes present → add only split routes, keep original default (split tunnel)
//   - No split routes       → replace default route via PPP (full tunnel)
func (t *Tunnel) setupRoutes(iface string, defRoute *ipv4.Route) {
	cfg := t.cfg

	// Always protect the tunnel: add a host route to the VPN gateway via the
	// original default gateway, so the VPN connection itself stays reachable
	// after the default route is changed.
	if defRoute != nil && cfg.GatewayIP != nil {
		gwRoute := ipv4.Route{
			Dest:    net.IPNet{IP: cfg.GatewayIP, Mask: net.CIDRMask(32, 32)},
			Gateway: defRoute.Gateway,
			Iface:   defRoute.Iface,
		}
		if err := t.routes.Add(gwRoute); err != nil {
			slog.Warn("failed to add gateway host route", "err", err)
		}
	}

	hasSplitRoutes := len(t.ipv4Cfg.SplitRoutes) > 0

	if hasSplitRoutes {
		// Split tunnel: VPN server only handles internal traffic.
		// Add per-network routes through PPP; leave the original default route
		// in place so internet traffic continues via the local gateway.
		for _, splitNet := range t.ipv4Cfg.SplitRoutes {
			if err := t.routes.Add(ipv4.Route{Dest: splitNet, Iface: iface}); err != nil {
				slog.Warn("failed to add split route", "cidr", splitNet.String(), "err", err)
			}
		}
	} else if cfg.HalfInternetRoutes {
		// Full tunnel via two /1 routes (avoids displacing DHCP default route).
		for _, cidr := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			_, ipNet, _ := net.ParseCIDR(cidr)
			if err := t.routes.Add(ipv4.Route{Dest: *ipNet, Iface: iface}); err != nil {
				slog.Warn("failed to add half-internet route", "cidr", cidr, "err", err)
			}
		}
	} else {
		// Full tunnel: replace the default route with PPP.
		if defRoute != nil {
			t.routes.Delete(*defRoute) //nolint:errcheck
		}
		if err := t.routes.Add(ipv4.Route{
			Dest:  net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Iface: iface,
		}); err != nil {
			slog.Warn("failed to set default route through PPP", "err", err)
		}
	}
}

// teardownNetwork restores routing and DNS to their pre-VPN state.
func (t *Tunnel) teardownNetwork() {
	cfg := t.cfg

	if cfg.SetDNS {
		if err := t.dns.Remove(t.ipv4Cfg.NS1, t.ipv4Cfg.NS2, t.ipv4Cfg.DNSSuffix); err != nil {
			slog.Warn("failed to restore DNS", "err", err)
		}
	}

	if cfg.SetRoutes && t.savedDefault != nil {
		// Only restore default route when we replaced it (no split routes, no half-internet).
		if len(t.ipv4Cfg.SplitRoutes) == 0 && !cfg.HalfInternetRoutes {
			t.routes.Add(*t.savedDefault) //nolint:errcheck
		}
	}
	slog.Info("Network configuration restored")
}

func (t *Tunnel) setState(s TunnelState) {
	t.state.Store(int32(s))
}

// findIfaceByIP polls net.Interfaces until it finds an interface with the
// given IP assigned, timing out after 60 seconds.
func findIfaceByIP(ip net.IP) (string, error) {
	deadline := time.Now().Add(60 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				addrs, _ := iface.Addrs()
				for _, addr := range addrs {
					var ifIP net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ifIP = v.IP
					case *net.IPAddr:
						ifIP = v.IP
					}
					if ifIP != nil && ifIP.Equal(ip) {
						return iface.Name, nil
					}
				}
			}
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("timeout waiting for interface with IP %s", ip)
		}
		<-ticker.C
	}
}
