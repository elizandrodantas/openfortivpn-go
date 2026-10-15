package auth

import (
	"fmt"
	"html"
	"regexp"
	"strings"
)

// sslvpnErrMsg matches the human-readable error FortiGate embeds as an HTML
// comment in its login error pages, e.g.:
//
//	<!--sslvpnerrmsg=Too many bad login attempts. Please try again in a few minutes.-->
var sslvpnErrMsg = regexp.MustCompile(`<!--\s*sslvpnerrmsg=(.*?)\s*-->`)

// gatewayMessage extracts the gateway's own error message from a response
// body, or "" if it didn't include one.
func gatewayMessage(body string) string {
	if m := sslvpnErrMsg.FindStringSubmatch(body); m != nil {
		return strings.TrimSpace(html.UnescapeString(m[1]))
	}
	return ""
}

// rejected builds the error for a login step the gateway didn't accept.
// It surfaces the gateway's own message when there is one, and never embeds
// the raw response body (full HTML pages) — that's already in the -v debug
// log ("httptunnel response").
func rejected(step string, status int, body string) error {
	if msg := gatewayMessage(body); msg != "" {
		return fmt.Errorf("%w: %s", ErrAuthFailed, msg)
	}
	return fmt.Errorf("%w: %s (unexpected HTTP %d response; run with -v to see it)", ErrAuthFailed, step, status)
}

// permissionDenied returns ErrPermission, with the gateway's own reason
// appended when it gave one.
func permissionDenied(body string) error {
	if msg := gatewayMessage(body); msg != "" {
		return fmt.Errorf("%w: %s", ErrPermission, msg)
	}
	return ErrPermission
}
