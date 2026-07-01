//go:build windows

package ipv4

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// winDNSManager implements DNSManager on Windows using netsh.
type winDNSManager struct {
	iface string
}

// NewDNSManager returns a DNSManager for Windows using netsh.
func NewDNSManager(_ bool) DNSManager {
	return &winDNSManager{}
}

func (d *winDNSManager) Add(iface string, _, ns1, ns2 net.IP, suffix string, _ bool) error {
	d.iface = iface
	if ns1 != nil {
		if err := d.setDNS(ns1.String(), "static"); err != nil {
			return err
		}
	}
	if ns2 != nil {
		if err := d.setDNS(ns2.String(), "add"); err != nil {
			return err
		}
	}
	return nil
}

func (d *winDNSManager) Remove(_ net.IP, _ net.IP, _ string) error {
	// Restore DHCP-assigned DNS
	out, err := exec.Command("netsh", "interface", "ip", "set", "dns",
		"name="+d.iface, "source=dhcp").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: netsh restore DNS: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *winDNSManager) setDNS(addr, mode string) error {
	args := []string{"interface", "ip", mode, "dns", "name=" + d.iface, "addr=" + addr}
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: netsh set dns %s: %w (%s)", addr, err, strings.TrimSpace(string(out)))
	}
	return nil
}
