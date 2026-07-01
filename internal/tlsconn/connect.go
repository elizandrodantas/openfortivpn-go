// Package tlsconn handles TLS dialing, proxy CONNECT tunneling, and
// certificate verification with SHA-256 pinning.
package tlsconn

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
)

// Dial establishes a TCP+TLS connection to the VPN gateway. If an HTTP proxy
// is configured via environment variables (HTTPS_PROXY, https_proxy, ALL_PROXY,
// all_proxy), it tunnels through it using HTTP CONNECT.
//
// Returns the *tls.Conn and the underlying net.Conn (for TCP_NODELAY etc.).
// The caller must close both on cleanup.
func Dial(ctx context.Context, cfg *config.Config) (*tls.Conn, net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", cfg.GatewayHost, cfg.GatewayPort)

	// Without an explicit deadline, a gateway that silently drops packets
	// (wrong port, firewall black-holing the connection) leaves DialContext
	// blocked for as long as the OS's own TCP retransmission timeout, which
	// can run to several minutes with no feedback to the user. Bound the
	// connect phase (TCP dial + TLS handshake) so failures surface quickly.
	dialCtx := ctx
	if cfg.ConnectTimeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(ctx, cfg.ConnectTimeout)
		defer cancel()
	}

	rawConn, err := dialRaw(dialCtx, addr)
	if err != nil {
		return nil, nil, fmt.Errorf("tlsconn: dial %s: %w", addr, describeDialErr(dialCtx, ctx, cfg.ConnectTimeout, err))
	}

	// Apply TCP_NODELAY — critical for PPP throughput (~3x improvement)
	if tc, ok := rawConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true) //nolint:errcheck
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("tlsconn: build TLS config: %w", err)
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(dialCtx); err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("tlsconn: TLS handshake: %w", describeDialErr(dialCtx, ctx, cfg.ConnectTimeout, err))
	}

	if err := VerifyCert(tlsConn, cfg); err != nil {
		tlsConn.Close()
		return nil, nil, err
	}

	return tlsConn, rawConn, nil
}

// describeDialErr distinguishes a connect-timeout from a user-initiated
// cancellation, so the two don't get reported with the same confusing
// "context canceled" message.
func describeDialErr(dialCtx, parentCtx context.Context, timeout time.Duration, err error) error {
	if errors.Is(dialCtx.Err(), context.DeadlineExceeded) && parentCtx.Err() == nil {
		return fmt.Errorf("connection timed out after %s (check host/port and network/firewall reachability, or raise --timeout): %w", timeout, err)
	}
	return err
}

// dialRaw opens a TCP connection, optionally through an HTTP proxy.
func dialRaw(ctx context.Context, addr string) (net.Conn, error) {
	proxy := proxyFromEnv()
	if proxy == "" {
		return (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}

	// Connect to proxy first
	proxyConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxy)
	if err != nil {
		return nil, fmt.Errorf("proxy connect to %s: %w", proxy, err)
	}

	// Send HTTP CONNECT
	req, _ := http.NewRequest(http.MethodConnect, "https://"+addr, nil)
	req.Header.Set("User-Agent", "openfortivpn-go")
	if err := req.Write(proxyConn); err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT write: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(proxyConn), req)
	if err != nil {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT response: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		proxyConn.Close()
		return nil, fmt.Errorf("proxy CONNECT returned %d", resp.StatusCode)
	}
	return proxyConn, nil
}

// buildTLSConfig constructs a tls.Config from VPN configuration.
//
// InsecureSkipVerify is always true here because FortiGate devices commonly
// use self-signed or non-standards-compliant certificates that Go's crypto/tls
// would reject during the handshake itself. Certificate verification is done
// manually via VerifyConnection after the handshake, matching OpenSSL's
// behaviour in the original C implementation.
func buildTLSConfig(cfg *config.Config) (*tls.Config, error) {
	// Load system CAs and optionally a custom CA file
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certificates in CA file %s", cfg.CAFile)
		}
	}

	tlsCfg := &tls.Config{
		ServerName:         cfg.ServerName(),
		MinVersion:         cfg.TLSMinVersion(),
		RootCAs:            pool,
		InsecureSkipVerify: true, // manual verification done in VerifyConnection below
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyConnectionState(cs, cfg, pool)
		},
	}

	// Client certificate (PEM files)
	if cfg.UserCert != "" && !strings.HasPrefix(cfg.UserCert, "pkcs11:") {
		cert, err := tls.LoadX509KeyPair(cfg.UserCert, cfg.UserKey)
		if err != nil {
			return nil, fmt.Errorf("loading client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// proxyFromEnv returns the proxy host:port from standard environment variables.
func proxyFromEnv() string {
	for _, env := range []string{"HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"} {
		if v := os.Getenv(env); v != "" {
			// Strip scheme if present
			v = strings.TrimPrefix(v, "http://")
			v = strings.TrimPrefix(v, "https://")
			v = strings.TrimSuffix(v, "/")
			return v
		}
	}
	return ""
}
