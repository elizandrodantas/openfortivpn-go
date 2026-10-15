package auth

import (
	"bytes"
	"fmt"
	"log/slog"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
	"github.com/elizandrodantas/openfortivpn-go/internal/userinput"
)

// With 'limit-user-logins' enabled, FortiGate accepts the credentials of a
// user that already has an open SSL VPN session but, instead of starting a
// new one, redirects the logincheck response to loginConfirmPath. That
// "Already Logged In" page links to limitUserConfirmPath ("Log in Anyway")
// and limitUserCancelPath; some firmwares also embed limitUserMarker
// (FortiClient's sslvpn.cpp checks for it). On yes, FortiClient requests
// limitUserConfirmPath with the new SVPNCOOKIE.
const (
	loginConfirmPath     = "/remote/loginconfirm"
	limitUserMarker      = "<!--fgt limit user-->"
	limitUserConfirmPath = "/remote/loginconfirm?action=login"
	limitUserCancelPath  = "/remote/loginconfirm?action=cancel"
	limitUserPrompt      = "You already have an open SSL VPN connection. Opening multiple connections is not permitted.\n" +
		"Disconnect your other connection and continue? [y/N]: "
)

// ConfirmLimitUser handles the gateway's "already logged in" prompt if body
// carries it: it asks the user (or uses cfg.ForceLogin) and, on yes, tells
// the gateway to drop the other session. handled reports whether body
// carried the prompt; when it did and err is nil, the caller should repeat
// the request that returned body. The confirmation may refresh the cookie
// held by c.
func ConfirmLimitUser(c *httptunnel.Client, cfg *config.Config, body []byte) (handled bool, err error) {
	if !bytes.Contains(body, []byte(limitUserMarker)) && !bytes.Contains(body, []byte(limitUserConfirmPath)) {
		return false, nil
	}
	slog.Info("Gateway reports another open SSL VPN session for this user (limit-user-logins)")

	disconnect := cfg.ForceLogin
	if !disconnect {
		disconnect, err = userinput.Confirm(limitUserPrompt)
		if err != nil {
			return true, fmt.Errorf("authentication: reading answer: %w", err)
		}
	}
	if !disconnect {
		// Release the pending login so it does not linger on the gateway.
		if _, err := c.Get(limitUserCancelPath); err != nil {
			slog.Debug("login cancel failed", "err", err)
		}
		return true, ErrAlreadyLoggedIn
	}

	slog.Info("Disconnecting the other SSL VPN session")
	resp, err := c.Get(limitUserConfirmPath)
	if err != nil {
		return true, fmt.Errorf("authentication: login confirm: %w", err)
	}
	if resp.StatusCode >= 400 {
		return true, fmt.Errorf("%w: login confirm returned status=%d", ErrAuthFailed, resp.StatusCode)
	}
	return true, nil
}

// followLoginConfirm handles a logincheck response that redirects (via
// document.location) to loginConfirmPath: it fetches that page and answers
// the "already logged in" prompt it carries.
func followLoginConfirm(c *httptunnel.Client, cfg *config.Config, body []byte) error {
	if !bytes.Contains(body, []byte("'"+loginConfirmPath+"'")) {
		return nil
	}
	resp, err := c.Get(loginConfirmPath)
	if err != nil {
		return fmt.Errorf("authentication: GET %s: %w", loginConfirmPath, err)
	}
	handled, err := ConfirmLimitUser(c, cfg, resp.Body)
	if err != nil {
		return err
	}
	if !handled {
		return fmt.Errorf("%w: unsupported %s page (status=%d); run with -vv to see it",
			ErrAuthFailed, loginConfirmPath, resp.StatusCode)
	}
	return nil
}
