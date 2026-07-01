//go:build linux

package ipv4

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

// netlinkRouteManager implements RouteManager using the Linux Netlink API.
type netlinkRouteManager struct{}

// NewRouteManager returns a RouteManager for Linux using netlink.
func NewRouteManager() RouteManager {
	return &netlinkRouteManager{}
}

func (m *netlinkRouteManager) GetDefault() (*Route, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("ipv4: netlink route list: %w", err)
	}
	for _, r := range routes {
		if r.Dst == nil || r.Dst.IP.Equal(net.IPv4zero) {
			iface, _ := net.InterfaceByIndex(r.LinkIndex)
			name := ""
			if iface != nil {
				name = iface.Name
			}
			return &Route{
				Dest:    net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
				Gateway: r.Gw,
				Iface:   name,
			}, nil
		}
	}
	return nil, ErrNoSuchRoute
}

func (m *netlinkRouteManager) Add(r Route) error {
	iface, err := net.InterfaceByName(r.Iface)
	if err != nil {
		return fmt.Errorf("ipv4: interface %q not found: %w", r.Iface, err)
	}
	dst := r.Dest
	route := &netlink.Route{
		LinkIndex: iface.Index,
		Dst:       &dst,
		Gw:        r.Gateway,
	}
	if err := netlink.RouteAdd(route); err != nil {
		return fmt.Errorf("ipv4: add route %s via %s: %w", r.Dest.String(), r.Gateway, err)
	}
	return nil
}

func (m *netlinkRouteManager) Delete(r Route) error {
	dst := r.Dest
	route := &netlink.Route{
		Dst: &dst,
		Gw:  r.Gateway,
	}
	if err := netlink.RouteDel(route); err != nil {
		return fmt.Errorf("ipv4: delete route %s: %w", r.Dest.String(), err)
	}
	return nil
}
