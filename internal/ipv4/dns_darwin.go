//go:build darwin

package ipv4

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

const resolverDir = "/etc/resolver"

// darwinDNS implements DNSManager on macOS.
//
// With --use-pppd: Apple's own /usr/sbin/pppd publishes DNS natively into
// the SCDynamicStore via "usepeerdns"+"serviceid" (wired in
// internal/ppp/pppd_unix.go) whenever the FortiGate sends DNS options during
// IPCP negotiation. That binary is Apple-signed and has built-in
// SystemConfiguration integration (confirmed via strings: ConfirmedServiceID,
// republish_dict, "SCDynamicStoreSetValue DNS/WINS") — matching the fields
// observed on a live, working official-FortiClient session. Add() is a no-op
// whenever this already happened (ipcpProvidedDNS == true).
//
// Full tunnel (internet routed through the VPN interface, the default utun
// backend): publish State:/Network/Service/<id>/{IPv4,DNS} ourselves, the
// way openconnect's vpnc-script does on macOS. The IPv4 entry carries
// InterfaceName + OverridePrimary, which is what makes configd promote the
// service's DNS to the unscoped default resolver instead of a per-interface
// scoped one (an earlier hand-rolled registration without OverridePrimary
// only ever got the scoped tier).
//
// Split tunnel, or if the publication above fails: /etc/resolver/<domain>
// files, discovering the domain via PTR lookup when the XML didn't supply
// one. This mechanism is NOT interface-bound: the kernel routes queries to
// the nameserver via the normal routing table, so the VPN DNS server is
// reached via the VPN interface using the VPN-assigned IP as source.
type darwinDNS struct {
	resolverFiles []string // files we created; removed on disconnect
	scKeys        []string // SCDynamicStore keys we published; removed on disconnect
}

// scServiceID is the SCDynamicStore service id used for our own DNS
// publication (distinct from the "openfortivpn" serviceid handed to pppd).
const scServiceID = "openfortivpn-go"

// NewDNSManager returns a macOS DNS manager.
func NewDNSManager(_ bool) DNSManager {
	return &darwinDNS{}
}

func (d *darwinDNS) Add(iface string, assignedIP, ns1, ns2 net.IP, suffix string, ipcpProvidedDNS bool) error {
	if ipcpProvidedDNS {
		// pppd's own usepeerdns+serviceid already published this natively.
		return nil
	}

	if routesInternetVia(iface) {
		err := d.publishService(iface, assignedIP, ns1, ns2, suffix)
		if err == nil {
			slog.Debug("published VPN DNS as primary resolver", "service", scServiceID, "iface", iface)
			flushDNSCache()
			return nil
		}
		slog.Warn("could not publish VPN DNS via SCDynamicStore — falling back to /etc/resolver", "err", err)
	}

	// Discover the domain if the VPN server didn't provide one.
	// PTR lookup of each nameserver via itself: e.g.
	//   203.0.113.10 → "dns01.example.corp." → "example.corp"
	if suffix == "" {
		suffix = discoverDomain(ns1, ns2)
		if suffix != "" {
			slog.Debug("DNS domain discovered via PTR", "suffix", suffix)
		}
	}

	if suffix == "" {
		slog.Warn("no DNS domain available — internal hostnames may not resolve; " +
			"set search= in the FortiGate DNS config")
		return nil
	}

	// Create /etc/resolver/<domain> so mDNSResponder and libresolv both use
	// the VPN nameservers for this domain without interface binding.
	if err := os.MkdirAll(resolverDir, 0755); err != nil {
		return fmt.Errorf("ipv4 dns: mkdir %s: %w", resolverDir, err)
	}

	path := resolverDir + "/" + suffix
	var sb strings.Builder
	fmt.Fprintf(&sb, "domain %s\n", suffix)
	fmt.Fprintf(&sb, "search %s\n", suffix)
	if ns1 != nil {
		fmt.Fprintf(&sb, "nameserver %s\n", ns1.String())
	}
	if ns2 != nil {
		fmt.Fprintf(&sb, "nameserver %s\n", ns2.String())
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("ipv4 dns: write %s: %w", path, err)
	}
	d.resolverFiles = append(d.resolverFiles, path)
	slog.Debug("created resolver file", "path", path)

	flushDNSCache()
	return nil
}

// publishService registers the VPN as a primary network service carrying
// its DNS servers, via scutil.
func (d *darwinDNS) publishService(iface string, assignedIP, ns1, ns2 net.IP, suffix string) error {
	var servers []string
	for _, ns := range []net.IP{ns1, ns2} {
		if ns != nil {
			servers = append(servers, ns.String())
		}
	}
	if len(servers) == 0 || assignedIP == nil {
		return fmt.Errorf("no nameservers or assigned IP to publish")
	}

	ipv4Key := "State:/Network/Service/" + scServiceID + "/IPv4"
	dnsKey := "State:/Network/Service/" + scServiceID + "/DNS"

	var sb strings.Builder
	sb.WriteString("d.init\n")
	fmt.Fprintf(&sb, "d.add Addresses * %s\n", assignedIP)
	sb.WriteString("d.add SubnetMasks * 255.255.255.255\n")
	fmt.Fprintf(&sb, "d.add Router %s\n", assignedIP)
	fmt.Fprintf(&sb, "d.add InterfaceName %s\n", iface)
	sb.WriteString("d.add OverridePrimary # 1\n")
	fmt.Fprintf(&sb, "set %s\n", ipv4Key)
	sb.WriteString("d.init\n")
	fmt.Fprintf(&sb, "d.add ServerAddresses * %s\n", strings.Join(servers, " "))
	if suffix != "" {
		fmt.Fprintf(&sb, "d.add DomainName %s\n", suffix)
		fmt.Fprintf(&sb, "d.add SearchDomains * %s\n", suffix)
	}
	fmt.Fprintf(&sb, "set %s\n", dnsKey)
	sb.WriteString("quit\n")

	// Record the keys before running, so a partial failure is still
	// cleaned up by Remove.
	d.scKeys = append(d.scKeys, ipv4Key, dnsKey)
	return runScutil(sb.String())
}

func runScutil(script string) error {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("scutil: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// routesInternetVia reports whether internet traffic is routed through
// iface, i.e. this is a full tunnel (default route or the two /1 routes
// from --half-internet-routes), as opposed to split tunneling.
func routesInternetVia(iface string) bool {
	if iface == "" {
		return false
	}
	out, err := exec.Command("route", "-n", "get", "1.1.1.1").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if ok && k == "interface" {
			return strings.TrimSpace(v) == iface
		}
	}
	return false
}

func (d *darwinDNS) Remove(_, _ net.IP, _ string) error {
	var errs []string
	if len(d.scKeys) > 0 {
		var sb strings.Builder
		for _, k := range d.scKeys {
			fmt.Fprintf(&sb, "remove %s\n", k)
		}
		sb.WriteString("quit\n")
		if err := runScutil(sb.String()); err != nil {
			errs = append(errs, err.Error())
		}
		d.scKeys = nil
	}
	for _, path := range d.resolverFiles {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("remove %s: %v", path, err))
		}
	}
	d.resolverFiles = nil

	flushDNSCache()

	if len(errs) > 0 {
		return fmt.Errorf("ipv4 dns remove: %s", strings.Join(errs, "; "))
	}
	return nil
}

// discoverDomain does a reverse-DNS lookup of each nameserver IP via the
// nameserver itself. Corporate DNS servers typically have PTR records like
// "dns01.example.corp." — we return the last two labels as the domain
// (e.g. "example.corp"). Times out after 3 s per server.
func discoverDomain(ns1, ns2 net.IP) string {
	for _, ns := range []net.IP{ns1, ns2} {
		if ns == nil {
			continue
		}
		nsAddr := ns.String() + ":53"
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "udp", nsAddr)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		names, err := r.LookupAddr(ctx, ns.String())
		cancel()
		if err != nil || len(names) == 0 {
			continue
		}
		fqdn := strings.TrimSuffix(names[0], ".")
		parts := strings.Split(fqdn, ".")
		if len(parts) >= 2 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
	}
	return ""
}

// flushDNSCache asks mDNSResponder to reload its config immediately instead
// of waiting for its own poll interval.
func flushDNSCache() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
