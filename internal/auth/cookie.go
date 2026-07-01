package auth

import (
	"context"
	"fmt"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
)

// CookieAuth uses a pre-existing SVPNCOOKIE session (--cookie flag).
type CookieAuth struct{}

func (a *CookieAuth) Authenticate(_ context.Context, c *httptunnel.Client, cfg *config.Config) (string, error) {
	if cfg.Cookie == "" {
		return "", fmt.Errorf("%w: no cookie provided", ErrAuthFailed)
	}
	c.SetCookie(cfg.Cookie)
	return cfg.Cookie, nil
}
