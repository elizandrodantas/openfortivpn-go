// Package config defines the VPN configuration structure and loading logic.
package config

import (
	"crypto/tls"
	"net"
	"time"
)

// Config holds all VPN configuration parameters. Zero values represent
// "not set" — callers should check IsSet methods or use defaults explicitly.
type Config struct {
	// Gateway
	GatewayHost    string
	GatewayPort    uint16
	GatewayIP      net.IP // resolved at connect time
	ConnectTimeout time.Duration

	// Credentials
	Username      string
	Password      string
	PasswordSet   bool
	OTP           string
	Cookie        string
	SAMLPort      uint16
	SAMLSessionID string
	OTPPrompt     string
	OTPDelay      time.Duration
	NoFTMPush     bool
	Pinentry      string

	// Network identity
	IfaceName string
	Realm     string
	SNI       string

	// Routing & DNS
	SetRoutes          bool
	SetDNS             bool
	PPPDUsePeerDNS     bool
	UseSyslog          bool
	UseResolvconf      bool
	HalfInternetRoutes bool

	// Reconnection
	Persistent time.Duration // 0 = disabled

	// pppd options (Unix)
	PPPDLog          string
	PPPDPlugin       string
	PPPDIPParam      string
	PPPDIfname       string
	PPPDCall         string
	PPPDAcceptRemote bool

	// FreeBSD ppp (legacy)
	PPPSystem string

	// TLS
	CAFile        string
	UserCert      string
	UserKey       string
	PEMPassphrase string
	PEMPassSet    bool
	InsecureSSL   bool
	MinTLS        uint16   // tls.VersionTLS10/11/12/13; 0 = default
	Seclevel1     bool     // append :@SECLEVEL=1 to cipher list
	CipherList    string   // OpenSSL-style; mapped to Go suites
	TrustedCerts  []string // SHA-256 hex digests for cert pinning
	UseEngine     bool     // PKCS#11 smartcard

	// HTTP
	UserAgent          string
	Hostcheck          string
	CheckVirtualDesktop string

	// Verbosity (-v -vv -vvv)
	Verbosity int
}

// DefaultConnectTimeout is how long Dial waits for the TCP connection and TLS
// handshake to complete before giving up, when no explicit timeout is set.
const DefaultConnectTimeout = 20 * time.Second

// Defaults returns a Config populated with safe production defaults.
func Defaults() *Config {
	return &Config{
		GatewayPort:    443,
		ConnectTimeout: DefaultConnectTimeout,
		SetRoutes:      true,
		SetDNS:         true,
		PPPDUsePeerDNS: false,
		MinTLS:         tls.VersionTLS12,
	}
}

// TLSMinVersion returns the Go tls version constant to use, falling back to
// TLS 1.2 when not set.
func (c *Config) TLSMinVersion() uint16 {
	if c.MinTLS != 0 {
		return c.MinTLS
	}
	return tls.VersionTLS12
}

// ServerName returns the TLS SNI hostname, falling back to GatewayHost.
func (c *Config) ServerName() string {
	if c.SNI != "" {
		return c.SNI
	}
	return c.GatewayHost
}

// SecondsToD converts a seconds count to a time.Duration.
func SecondsToD(secs uint) time.Duration {
	return time.Duration(secs) * time.Second
}
