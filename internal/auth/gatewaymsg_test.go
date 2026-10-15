package auth

import (
	"errors"
	"strings"
	"testing"
)

const lockoutPage = `<!DOCTYPE html>
<html><head><title>SSL VPN Remote Access Web Portal</title></head>
<body class="main"><table class="container">
<!--sslvpnerrmsg=Too many bad login attempts. Please try again in a few minutes.-->
<h2 id="sslvpn_logindisable_errmsg"></h2></table></body></html>
`

func TestRejectedUsesGatewayMessage(t *testing.T) {
	err := rejected("login", 200, lockoutPage)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
	want := "authentication failed: Too many bad login attempts. Please try again in a few minutes."
	if err.Error() != want {
		t.Fatalf("err = %q, want %q", err, want)
	}
}

func TestRejectedNeverEmbedsBody(t *testing.T) {
	err := rejected("login", 200, "<html><body>something else</body></html>")
	if strings.Contains(err.Error(), "<html") {
		t.Fatalf("error leaks response body: %q", err)
	}
	if !strings.Contains(err.Error(), "HTTP 200") {
		t.Fatalf("error should mention the status: %q", err)
	}
}

func TestPermissionDeniedAppendsGatewayMessage(t *testing.T) {
	err := permissionDenied(`<!--sslvpnerrmsg=Permission denied.-->`)
	if !errors.Is(err, ErrPermission) || !strings.HasSuffix(err.Error(), ": Permission denied.") {
		t.Fatalf("err = %q", err)
	}
	if permissionDenied("ret=0,permission_denied") != ErrPermission {
		t.Fatal("without a gateway message, want bare ErrPermission")
	}
}
