//go:build darwin || freebsd

package ipv4

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// execRouteManager implements RouteManager by shelling out to the `route` command
// (macOS/FreeBSD). This avoids the complexity of raw PF_ROUTE socket programming
// while maintaining full functionality.
type execRouteManager struct{}

// NewRouteManager returns a RouteManager for macOS/FreeBSD using the route command.
func NewRouteManager() RouteManager {
	return &execRouteManager{}
}

func (m *execRouteManager) GetDefault() (*Route, error) {
	out, err := exec.Command("netstat", "-f", "inet", "-rn").Output()
	if err != nil {
		return nil, fmt.Errorf("ipv4: netstat: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "default" {
			gw := net.ParseIP(fields[1])
			iface := ""
			if len(fields) >= 6 {
				iface = fields[5]
			}
			return &Route{
				Dest:    net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				Gateway: gw,
				Iface:   iface,
			}, nil
		}
	}
	return nil, ErrNoSuchRoute
}

func (m *execRouteManager) Add(r Route) error {
	dest := r.Dest.String()
	if r.Dest.IP.Equal(net.IPv4zero) {
		dest = "default"
	}
	args := []string{"add", dest}
	if r.Iface != "" {
		args = append(args, "-interface", r.Iface)
	} else {
		args = append(args, r.Gateway.String())
	}
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: route add %s: %w (%s)", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (m *execRouteManager) Delete(r Route) error {
	dest := r.Dest.String()
	if r.Dest.IP.Equal(net.IPv4zero) {
		dest = "default"
	}
	out, err := exec.Command("route", "delete", dest).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipv4: route delete %s: %w (%s)", dest, err, strings.TrimSpace(string(out)))
	}
	return nil
}
