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
			return "", fmt.Errorf("authentication: reading password: %w", err)
		}
	}

	// Initial logincheck uses ajax=1 so FortiGate returns the compact
	// "ret=2,tokeninfo=..." format we can parse for the challenge fields.
	values := url.Values{
		"username":   {cfg.Username},
		"credential": {pass},
		"ajax":       {"1"},
	}
	setJustLoggedIn(values)
	if cfg.Realm != "" {
		values.Set("realm", cfg.Realm)
	}

	resp, err := c.PostForm("/remote/logincheck", values)
	if err != nil {
		return "", fmt.Errorf("authentication: logincheck: %w", err)
	}

	body := string(resp.Body)
	slog.Debug("auth logincheck response", "status", resp.StatusCode)

	if strings.Contains(body, "permission_denied") || resp.StatusCode == 403 {
		return "", permissionDenied(body)
	}

	if resp.StatusCode == 200 && strings.Contains(body, "ret=1") {
		return a.cookieOrRedir(c, cfg, body)
	}

	// 401 or compact challenge with tokeninfo — 2FA required
	if resp.StatusCode == 401 || strings.Contains(body, "tokeninfo") {
		return a.handle2FA(ctx, c, cfg, body, pass)
	}

	return "", rejected("login", resp.StatusCode, body)
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
		setJustLoggedIn(values)
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
			return "", fmt.Errorf("authentication: FTM push: %w", err)
		}
		if resp.StatusCode == 200 {
			return a.cookieOrRedir(c, cfg, string(resp.Body))
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
			return "", fmt.Errorf("authentication: reading OTP: %w", err)
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
	setJustLoggedIn(values)

	resp, err := c.PostForm("/remote/logincheck", values)
	if err != nil {
		return "", fmt.Errorf("authentication: OTP logincheck: %w", err)
	}

	if resp.StatusCode == 200 {
		return a.cookieOrRedir(c, cfg, string(resp.Body))
	}
	return "", rejected("one-time password", resp.StatusCode, string(resp.Body))
}

// setJustLoggedIn adds the fields FortiClient appends to every logincheck
// POST. Without just_logged_in=1, a gateway with 'limit-user-logins' denies
// the login outright (sslvpn_login_permission_denied) when the user already
// has an open session, instead of offering to disconnect it.
func setJustLoggedIn(values url.Values) {
	values.Set("redir", "/remote/index")
	values.Set("just_logged_in", "1")
}

// cookieOrRedir returns the current cookie if already set on c. If the body
// contains a redir= field (compact format from ajax=1 responses), or an
// HTML action= URL (full-page responses), it follows that URL to retrieve
// the SVPNCOOKIE from the redirect target's Set-Cookie header. Either
// response may carry the "already logged in" prompt, which is handled via
// ConfirmLimitUser.
func (a *PasswordAuth) cookieOrRedir(c *httptunnel.Client, cfg *config.Config, body string) (string, error) {
	if _, err := ConfirmLimitUser(c, cfg, []byte(body)); err != nil {
		return "", err
	}
	if err := followLoginConfirm(c, cfg, []byte(body)); err != nil {
		return "", err
	}
	if cookie := c.Cookie(); cookie != "" {
		return cookie, nil
	}
	if strings.Contains(body, "permission_denied") {
		return "", permissionDenied(body)
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
	resp, err := c.Get(redir)
	if err != nil {
		return "", fmt.Errorf("authentication: redir GET %s: %w", redir, err)
	}
	if _, err := ConfirmLimitUser(c, cfg, resp.Body); err != nil {
		return "", err
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

