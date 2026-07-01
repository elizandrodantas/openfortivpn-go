package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/httptunnel"
	"github.com/elizandrodantas/openfortivpn-go/internal/userinput"
)

// PasswordAuth handles username/password login including OTP and FTM push.
type PasswordAuth struct{}

func (a *PasswordAuth) Authenticate(ctx context.Context, c *httptunnel.Client, cfg *config.Config) (string, error) {
	pass := cfg.Password
	if !cfg.PasswordSet {
		var err error
		pass, err = userinput.ReadPassword(ctx, cfg.Pinentry, "openfortivpn", "Password: ")
		if err != nil {
			return "", fmt.Errorf("auth: reading password: %w", err)
		}
	}

	// Initial logincheck uses ajax=1 so FortiGate returns the compact
	// "ret=2,tokeninfo=..." format we can parse for the challenge fields.
	values := url.Values{
		"username":   {cfg.Username},
		"credential": {pass},
		"ajax":       {"1"},
	}
	if cfg.Realm != "" {
		values.Set("realm", cfg.Realm)
	}

	resp, err := c.PostForm("/remote/logincheck", values)
	if err != nil {
		return "", fmt.Errorf("auth: logincheck: %w", err)
	}

	body := string(resp.Body)
	slog.Debug("auth logincheck response", "status", resp.StatusCode)

	if strings.Contains(body, "permission_denied") || resp.StatusCode == 403 {
		return "", ErrPermission
	}

	if resp.StatusCode == 200 && strings.Contains(body, "ret=1") {
		return a.cookieOrRedir(c, body)
	}

	// 401 or compact challenge with tokeninfo — 2FA required
	if resp.StatusCode == 401 || strings.Contains(body, "tokeninfo") {
		return a.handle2FA(ctx, c, cfg, body, pass)
	}

	return "", fmt.Errorf("%w: unexpected response status=%d body=%q", ErrAuthFailed, resp.StatusCode, body)
}

func (a *PasswordAuth) handle2FA(ctx context.Context, c *httptunnel.Client, cfg *config.Config, body, pass string) (string, error) {
	// Extract all challenge fields from the compact "ret=2,key=val,..." body.
	ch := parseFortiBody(body)
	magic := ch["magic"]
	reqid := ch["reqid"]
	polid := ch["polid"]
	grp := ch["grp"]
	portal := ch["portal"]
	peer := ch["peer"]

	// FTM (FortiToken Mobile) push
	if strings.Contains(body, "ftm_push") && !cfg.NoFTMPush {
		slog.Info("Sending FTM push notification...")

		// FTM push uses the same field layout as the OTP POST (no ajax=1).
		values := url.Values{
			"username": {cfg.Username},
			"realm":    {cfg.Realm},
			"reqid":    {reqid},
			"polid":    {polid},
			"grp":      {grp},
			"portal":   {portal},
			"peer":     {peer},
			"ftmpush":  {"1"},
		}
		if magic != "" {
			values.Set("magic", magic)
		}

		if cfg.OTPDelay > 0 {
			slog.Info("Waiting before FTM push", "delay", cfg.OTPDelay)
			select {
			case <-time.After(cfg.OTPDelay):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		resp, err := c.PostForm("/remote/logincheck", values)
		if err != nil {
			return "", fmt.Errorf("auth: FTM push: %w", err)
		}
		if resp.StatusCode == 200 {
			return a.cookieOrRedir(c, string(resp.Body))
		}
	}

	// Manual OTP entry
	otp := cfg.OTP
	if otp == "" {
		prompt := cfg.OTPPrompt
		if prompt == "" {
			prompt = "One-time password: "
		}
		var err error
		otp, err = userinput.ReadLine(prompt)
		if err != nil {
			return "", fmt.Errorf("auth: reading OTP: %w", err)
		}
	}

	// OTP POST matches the C implementation exactly (http.c line 819-822):
	//   username=U&realm=R&reqid=Q&polid=P&grp=G&portal=O&peer=E&code=C&code2=&magic=M
	//
	// Crucially: NO ajax=1. Without it, FortiGate responds with a full HTTP
	// response that includes Set-Cookie: SVPNCOOKIE= instead of the compact
	// "ret=1,redir=..." text body returned when ajax=1 is set.
	values := url.Values{
		"username": {cfg.Username},
		"realm":    {cfg.Realm},
		"reqid":    {reqid},
		"polid":    {polid},
		"grp":      {grp},
		"portal":   {portal},
		"peer":     {peer},
		"code":     {otp},
		"code2":    {""},
		"magic":    {magic},
	}

	resp, err := c.PostForm("/remote/logincheck", values)
	if err != nil {
		return "", fmt.Errorf("auth: OTP logincheck: %w", err)
	}

	if resp.StatusCode == 200 {
		return a.cookieOrRedir(c, string(resp.Body))
	}
	return "", fmt.Errorf("%w: OTP rejected (status=%d body=%s)", ErrAuthFailed, resp.StatusCode, string(resp.Body))
}

// cookieOrRedir returns the current cookie if already set on c. If the body
// contains a redir= field (compact format from ajax=1 responses), or an
// HTML action= URL (full-page responses), it follows that URL to retrieve
// the SVPNCOOKIE from the redirect target's Set-Cookie header.
func (a *PasswordAuth) cookieOrRedir(c *httptunnel.Client, body string) (string, error) {
	if cookie := c.Cookie(); cookie != "" {
		return cookie, nil
	}

	// Try compact FortiGate body format first (redir=URL)
	redir := parseFortiBody(body)["redir"]

	// Fallback: extract HTML form action= attribute
	if redir == "" {
		redir = extractHTMLAction(body)
	}

	if redir == "" {
		return "", ErrNoCookie
	}

	slog.Debug("auth: following redir for cookie", "url", redir)
	_, err := c.Get(redir)
	if err != nil {
		return "", fmt.Errorf("auth: redir GET %s: %w", redir, err)
	}

	if cookie := c.Cookie(); cookie != "" {
		return cookie, nil
	}
	return "", ErrNoCookie
}

// parseFortiBody parses FortiGate's comma-delimited body format:
//
//	ret=2,magic=abc,redir=/remote/foo?a=1&b=2,chal_msg=Enter token
//
// The top-level delimiter is ',' — values may contain '&' and '=' freely
// (e.g. URL query strings), so we split only on the first '=' per field.
func parseFortiBody(body string) map[string]string {
	out := make(map[string]string)
	for _, field := range strings.Split(body, ",") {
		eq := strings.IndexByte(field, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(field[:eq])
		if key != "" {
			out[key] = field[eq+1:]
		}
	}
	return out
}

// extractHTMLAction finds the action= attribute in an HTML form body.
// The C implementation (get_action_url) tokenises on space/quote/CRLF and
// looks for "action=" followed by the next token as the value.
func extractHTMLAction(body string) string {
	const key = "action="
	idx := strings.Index(body, key)
	if idx == -1 {
		return ""
	}
	rest := body[idx+len(key):]
	if len(rest) == 0 {
		return ""
	}
	// Value is typically quoted: action="/remote/..."
	if rest[0] == '"' {
		end := strings.IndexByte(rest[1:], '"')
		if end == -1 {
			return ""
		}
		return rest[1 : 1+end]
	}
	// Unquoted: read until whitespace
	end := strings.IndexAny(rest, " \t\r\n>")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

