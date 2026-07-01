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
	gw := r.Gateway.String()
	out, err := exec.Command("route", "ADD", dest, "MASK", mask, gw).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: route ADD %s: %w (%s)", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *winRouteManager) Delete(r Route) error {
	dest := r.Dest.IP.String()
	out, err := exec.Command("route", "DELETE", dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: route DELETE %s: %w (%s)", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}
