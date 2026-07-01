package tlsconn

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
)

var (
	ErrCertValidation  = errors.New("tlsconn: certificate validation failed")
	ErrCertPinMismatch = errors.New("tlsconn: certificate digest not in trusted-cert whitelist")
)

// verifyConnectionState is registered as tls.Config.VerifyConnection so that
// it runs after the TLS handshake completes but before the connection is used.
// This allows us to handle non-standards-compliant FortiGate self-signed
// certificates (which Go's crypto/tls would otherwise reject during the
// handshake itself) while still enforcing chain validation or SHA-256 pinning.
//
// Precedence:
//  1. InsecureSSL=true  → accept everything (user explicitly opted out)
//  2. TrustedCerts set  → accept only if SHA-256 digest matches whitelist
//  3. Default           → standard X.509 chain + hostname verification;
//     on failure, print the digest and instruct the user to pin it
func verifyConnectionState(cs tls.ConnectionState, cfg *config.Config, roots *x509.CertPool) error {
	if len(cs.PeerCertificates) == 0 {
		return fmt.Errorf("%w: no peer certificate received", ErrCertValidation)
	}
	cert := cs.PeerCertificates[0]

	digest := sha256.Sum256(cert.Raw)
	hexDigest := hex.EncodeToString(digest[:])

	if cfg.InsecureSSL {
		return nil
	}

	if len(cfg.TrustedCerts) > 0 {
		if isPinned(hexDigest, cfg.TrustedCerts) {
			return nil
		}
		return fmt.Errorf("%w\n  server certificate digest : %s\n  expected one of           : %s",
			ErrCertPinMismatch, hexDigest, strings.Join(cfg.TrustedCerts, ", "))
	}

	// No pinning configured: perform standard X.509 chain + hostname verification.
	// We build the intermediate pool from the certificates supplied in the chain.
	intermediates := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       cfg.ServerName(),
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("%w: %v\n\n"+
			"  The server presented a certificate that could not be verified.\n"+
			"  If this is your gateway's self-signed certificate, add:\n\n"+
			"    --trusted-cert=%s",
			ErrCertValidation, err, hexDigest)
	}
	return nil
}

// VerifyCert is kept for compatibility with callers that hold a *tls.Conn.
func VerifyCert(conn *tls.Conn, cfg *config.Config) error {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("%w: no peer certificate", ErrCertValidation)
	}
	cert := state.PeerCertificates[0]
	digest := sha256.Sum256(cert.Raw)
	hexDigest := hex.EncodeToString(digest[:])

	if cfg.InsecureSSL {
		return nil
	}
	if len(cfg.TrustedCerts) > 0 && !isPinned(hexDigest, cfg.TrustedCerts) {
		return fmt.Errorf("%w\n  server digest: %s", ErrCertPinMismatch, hexDigest)
	}
	return nil
}

func isPinned(digest string, whitelist []string) bool {
	for _, trusted := range whitelist {
		if strings.EqualFold(digest, trusted) {
			return true
		}
	}
	return false
}
