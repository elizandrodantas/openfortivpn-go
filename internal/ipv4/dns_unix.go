//go:build !windows && !darwin

package ipv4

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const resolvConf = "/etc/resolv.conf"

// resolvConfDNS implements DNSManager by editing /etc/resolv.conf directly
// or delegating to the resolvconf utility.
type resolvConfDNS struct {
	useResolvconf bool
	backup        string // original resolv.conf content
}

// NewDNSManager returns a DNSManager for Unix-like systems.
func NewDNSManager(useResolvconf bool) DNSManager {
	return &resolvConfDNS{useResolvconf: useResolvconf}
}

func (d *resolvConfDNS) Add(_ string, _, ns1, ns2 net.IP, suffix string, _ bool) error {
	if d.useResolvconf {
		return d.addViaResolvconf(ns1, ns2, suffix)
	}
	return d.addToResolvConf(ns1, ns2, suffix)
}

func (d *resolvConfDNS) Remove(ns1, ns2 net.IP, suffix string) error {
	if d.useResolvconf {
		return d.removeViaResolvconf()
	}
	return d.restoreResolvConf()
}

func (d *resolvConfDNS) addToResolvConf(ns1, ns2 net.IP, suffix string) error {
	existing, err := os.ReadFile(resolvConf)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("ipv4: read %s: %w", resolvConf, err)
	}
	d.backup = string(existing)

	var sb strings.Builder
	if ns1 != nil {
		fmt.Fprintf(&sb, "nameserver %s\n", ns1.String())
	}
	if ns2 != nil {
		fmt.Fprintf(&sb, "nameserver %s\n", ns2.String())
	}
	if suffix != "" {
		fmt.Fprintf(&sb, "search %s\n", suffix)
	}
	sb.WriteString(d.backup)

	if err := os.WriteFile(resolvConf, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("ipv4: write %s: %w", resolvConf, err)
	}
	return nil
}

func (d *resolvConfDNS) restoreResolvConf() error {
	if d.backup == "" {
		return nil
	}
	if err := os.WriteFile(resolvConf, []byte(d.backup), 0644); err != nil {
		return fmt.Errorf("ipv4: restore %s: %w", resolvConf, err)
	}
	return nil
}

func (d *resolvConfDNS) addViaResolvconf(ns1, ns2 net.IP, suffix string) error {
	var sb strings.Builder
	if ns1 != nil {
		fmt.Fprintf(&sb, "nameserver %s\n", ns1.String())
	}
	if ns2 != nil {
		fmt.Fprintf(&sb, "nameserver %s\n", ns2.String())
	}
	if suffix != "" {
		fmt.Fprintf(&sb, "search %s\n", suffix)
	}
	cmd := exec.Command("resolvconf", "-a", "ppp0", "-m", "0", "-x")
	cmd.Stdin = strings.NewReader(sb.String())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: resolvconf -a: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *resolvConfDNS) removeViaResolvconf() error {
	out, err := exec.Command("resolvconf", "-d", "ppp0").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: resolvconf -d: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}
