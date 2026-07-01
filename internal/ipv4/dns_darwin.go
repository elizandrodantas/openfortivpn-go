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
// Primary path: Apple's own /usr/sbin/pppd publishes DNS natively into the
// SCDynamicStore via "usepeerdns"+"serviceid" (wired in
// internal/ppp/pppd_unix.go) whenever the FortiGate sends DNS options during
// IPCP negotiation. That binary is Apple-signed and has built-in
// SystemConfiguration integration (confirmed via strings: ConfirmedServiceID,
// republish_dict, "SCDynamicStoreSetValue DNS/WINS") — matching the fields
// observed on a live, working official-FortiClient session. Add() is a no-op
// whenever this already happened (ipcpProvidedDNS == true).
//
// Fallback path: if the peer didn't provide DNS via IPCP (some FortiGate
// configs only advertise DNS in the XML config, not IPCP), pppd's native
// mechanism has nothing to publish, so we fall back to /etc/resolver/<domain>
// files, discovering the domain via PTR lookup when the XML didn't supply
// one. This mechanism is NOT interface-bound: the kernel routes queries to
// the nameserver via the normal routing table, so the VPN DNS server is
// reached via the VPN interface using the VPN-assigned IP as source.
//
// A true global-default-resolver override (what the official FortiClient
// achieves via its own tunnel) was also attempted here via a hand-rolled
// State:/Network/Service/<id>/{DNS,IPv4,VPN} SCDynamicStore registration, but
// live testing showed macOS only promotes it to a per-interface SCOPED
// resolver, not the unscoped default — that tier appears reserved for
// privileged NetworkExtension providers and isn't reachable from a plain,
// unsigned CLI binary.
type darwinDNS struct {
	resolverFiles []string // files we created; removed on disconnect
}

// NewDNSManager returns a macOS DNS manager.
func NewDNSManager(_ bool) DNSManager {
	return &darwinDNS{}
}

func (d *darwinDNS) Add(_ string, _, ns1, ns2 net.IP, suffix string, ipcpProvidedDNS bool) error {
	if ipcpProvidedDNS {
		// pppd's own usepeerdns+serviceid already published this natively.
		return nil
	}
	slog.Info("VPN peer did not provide DNS via IPCP — falling back to /etc/resolver")

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

func (d *darwinDNS) Remove(_, _ net.IP, _ string) error {
	var errs []string
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
