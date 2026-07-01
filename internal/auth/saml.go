package auth

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
)

// SAMLAuth handles SAML browser-based login via a local HTTP redirect server.
type SAMLAuth struct{}

func (a *SAMLAuth) Authenticate(ctx context.Context, c *httptunnel.Client, cfg *config.Config) (string, error) {
	// Start local HTTP server to receive the SAML callback
	sessionCh, err := httptunnel.ServeSAML(ctx, cfg.SAMLPort)
	if err != nil {
		return "", fmt.Errorf("auth: SAML server: %w", err)
	}

	loginURL := httptunnel.SAMLLoginURL(cfg.GatewayHost, cfg.GatewayPort, cfg.SAMLPort)
	slog.Info("Open the following URL in your browser to complete SAML login", "url", loginURL)
	fmt.Printf("\n  %s\n\n", loginURL)

	// Wait for the callback with the session ID
	var sessionID string
	select {
	case sessionID = <-sessionCh:
	case <-ctx.Done():
		return "", ctx.Err()
	}

	slog.Info("SAML session ID received, completing authentication")

	// POST the session ID to the gateway
	resp, err := c.Get(fmt.Sprintf("/remote/saml/auth_id?id=%s", sessionID))
	if err != nil {
		return "", fmt.Errorf("auth: SAML auth_id: %w", err)
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%w: SAML auth_id returned %d", ErrAuthFailed, resp.StatusCode)
	}

	cookie := c.Cookie()
	if cookie == "" {
		return "", ErrNoCookie
	}
	return cookie, nil
}
