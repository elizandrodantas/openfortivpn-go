// Package ipv4 manages VPN routing table changes and DNS configuration.
package ipv4

import (
	"errors"
	"net"
)

var (
	ErrPermission   = errors.New("ipv4: insufficient privileges")
	ErrNoSuchRoute  = errors.New("ipv4: route not found")
)

// Route describes a routing table entry.
type Route struct {
	Dest    net.IPNet
	Gateway net.IP
	Iface   string
	Metric  int
}

// RouteManager adds and removes routes from the OS routing table.
type RouteManager interface {
	// GetDefault returns the current default route (0.0.0.0/0).
	GetDefault() (*Route, error)
	// Add adds a route. Returns ErrPermission if not root.
	Add(r Route) error
	// Delete deletes a route. Returns ErrNoSuchRoute if not present.
	Delete(r Route) error
}

// DNSManager updates the system DNS configuration.
type DNSManager interface {
	// Add configures VPN nameservers as active resolvers. iface is the VPN
	// tunnel interface (e.g. "ppp0") and assignedIP is the point-to-point IP
	// assigned to that interface. ipcpProvidedDNS indicates whether the VPN
	// peer already supplied DNS via PPP IPCP negotiation — on macOS this
	// means Apple's pppd already published it natively, so no further
	// action is needed unless this is false.
	Add(iface string, assignedIP, ns1, ns2 net.IP, suffix string, ipcpProvidedDNS bool) error
	// Remove restores the original resolver configuration.
	Remove(ns1, ns2 net.IP, suffix string) error
}

// Config holds the IPv4 settings received from the VPN gateway XML config.
type Config struct {
	AssignedIP net.IP
	Netmask    net.IP
	NS1        net.IP
	NS2        net.IP
	DNSSuffix  string
	SplitRoutes []net.IPNet
}
