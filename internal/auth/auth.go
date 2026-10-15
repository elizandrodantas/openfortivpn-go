// Package auth implements VPN authentication methods.
package auth

import (
	"context"
	"errors"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
)

var (
	ErrAuthFailed      = errors.New("authentication failed")
	ErrPermission      = errors.New("authentication: permission denied by the gateway")
	ErrNoCookie        = errors.New("authentication: gateway did not return a session cookie (SVPNCOOKIE)")
	ErrNeedOTP         = errors.New("authentication: one-time password required")
	ErrNeedFTMPush     = errors.New("authentication: FTM push required")
	ErrAlreadyLoggedIn = errors.New("authentication: another SSL VPN session is open for this user and was kept")
)

// Authenticator authenticates to the VPN gateway and returns the SVPNCOOKIE.
type Authenticator interface {
	Authenticate(ctx context.Context, c *httptunnel.Client, cfg *config.Config) (cookie string, err error)
}

// New returns the appropriate Authenticator based on the config.
func New(cfg *config.Config) Authenticator {
	switch {
	case cfg.Cookie != "":
		return &CookieAuth{}
	case cfg.SAMLPort != 0:
		return &SAMLAuth{}
	default:
		return &PasswordAuth{}
	}
}
