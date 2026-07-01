//go:build windows

package ipv4

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// winRouteManager implements RouteManager on Windows using the `route` command.
type winRouteManager struct{}

// NewRouteManager returns a RouteManager for Windows using route.exe.
func NewRouteManager() RouteManager {
	return &winRouteManager{}
}

func (m *winRouteManager) GetDefault() (*Route, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").Output()
	if err != nil {
		return nil, fmt.Errorf("ipv4: route print: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
			gw := net.ParseIP(fields[2])
			return &Route{
				Dest:    net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				Gateway: gw,
			}, nil
		}
	}
	return nil, ErrNoSuchRoute
}

func (m *winRouteManager) Add(r Route) error {
	dest := r.Dest.IP.String()
	mask := net.IP(r.Dest.Mask).String()

	// Routes through the PPP/TUN interface (split-tunnel, default-route
	// replacement, half-internet) are built with only Iface set, no
	// Gateway — classic route.exe still requires a gateway argument, so
	// resolve the interface's own address and use that: Windows treats a
	// gateway matching a locally-assigned address as reachable via that
	// interface, which is the standard way to route over a point-to-point
	// adapter like this one.
	gw := r.Gateway
	if gw == nil {
		if r.Iface == "" {
			return fmt.Errorf("ipv4: route ADD %s: no gateway or interface specified", dest)
		}
		ip, err := ifaceIPv4(r.Iface)
		if err != nil {
			return fmt.Errorf("ipv4: route ADD %s: resolve gateway for interface %s: %w", dest, r.Iface, err)
		}
		gw = ip
	}

	out, err := exec.Command("route", "ADD", dest, "MASK", mask, gw.String()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: route ADD %s: %w (%s)", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ifaceIPv4 returns the first IPv4 address assigned to the named interface.
func ifaceIPv4(name string) (net.IP, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if ip4 := ip.To4(); ip4 != nil {
			return ip4, nil
		}
	}
	return nil, fmt.Errorf("no IPv4 address assigned to interface %s", name)
}

func (m *winRouteManager) Delete(r Route) error {
	dest := r.Dest.IP.String()
	out, err := exec.Command("route", "DELETE", dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: route DELETE %s: %w (%s)", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}
