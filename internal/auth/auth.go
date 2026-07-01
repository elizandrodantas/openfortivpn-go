// Package auth implements VPN authentication methods.
package auth

import (
	"context"
	"errors"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
)

var (
	ErrAuthFailed    = errors.New("auth: authentication failed")
	ErrPermission    = errors.New("auth: permission denied by gateway")
	ErrNoCookie      = errors.New("auth: no SVPNCOOKIE in response")
	ErrNeedOTP       = errors.New("auth: one-time password required")
	ErrNeedFTMPush   = errors.New("auth: FTM push required")
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
