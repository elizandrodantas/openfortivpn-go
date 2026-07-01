// Package httptunnel implements a minimal HTTP/1.1 client over a raw *tls.Conn.
//
// net/http.Client cannot be used here because the same TLS connection is later
// "upgraded" to a PPP carrier after GET /remote/sslvpn-tunnel — surrendering
// the connection to an http.Transport would make it inaccessible for PPP I/O.
package httptunnel

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// Client sends HTTP/1.1 requests over a raw *tls.Conn and reads responses,
// keeping the connection accessible for PPP upgrade. Not safe for concurrent use.
type Client struct {
	conn   *tls.Conn
	bufr   *bufio.Reader
	host   string
	cookie string
	ua     string
}

// NewClient creates a Client wrapping conn. host is the HTTP Host header value.
func NewClient(conn *tls.Conn, host string, userAgent string) *Client {
	if userAgent == "" {
		userAgent = "Mozilla/5.0 openfortivpn-go"
	}
	return &Client{
		conn: conn,
		bufr: bufio.NewReader(conn),
		host: host,
		ua:   userAgent,
	}
}

// SetCookie stores the SVPNCOOKIE value to be sent on subsequent requests.
func (c *Client) SetCookie(cookie string) {
	c.cookie = cookie
}

// Cookie returns the current SVPNCOOKIE value.
func (c *Client) Cookie() string {
	return c.cookie
}

// Conn exposes the raw TLS connection, used to activate PPP tunnel mode.
func (c *Client) Conn() *tls.Conn {
	return c.conn
}

// Response holds the parsed HTTP response.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Get sends an HTTP GET request and returns the response.
func (c *Client) Get(path string) (*Response, error) {
	return c.Do(http.MethodGet, path, "", "")
}

// PostForm sends an HTTP POST with URL-encoded body.
func (c *Client) PostForm(path string, values url.Values) (*Response, error) {
	body := values.Encode()
	return c.Do(http.MethodPost, path, "application/x-www-form-urlencoded", body)
}

// Do sends an HTTP request with the given method, path, content-type and body.
func (c *Client) Do(method, path, contentType, body string) (*Response, error) {
	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(c.host)
	sb.WriteString("\r\n")
	sb.WriteString("User-Agent: ")
	sb.WriteString(c.ua)
	sb.WriteString("\r\n")
	if c.cookie != "" {
		sb.WriteString("Cookie: SVPNCOOKIE=")
		sb.WriteString(c.cookie)
		sb.WriteString("\r\n")
	}
	if contentType != "" {
		sb.WriteString("Content-Type: ")
		sb.WriteString(contentType)
		sb.WriteString("\r\n")
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}
	sb.WriteString("Connection: keep-alive\r\n")
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	if _, err := io.WriteString(c.conn, sb.String()); err != nil {
		return nil, fmt.Errorf("httptunnel: write request: %w", err)
	}

	// http.ReadResponse handles chunked encoding and Content-Length automatically,
	// while leaving the underlying conn untouched.
	resp, err := http.ReadResponse(c.bufr, nil)
	if err != nil {
		return nil, fmt.Errorf("httptunnel: read response: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httptunnel: read body: %w", err)
	}

	// Extract SVPNCOOKIE — case-insensitive name match via resp.Cookies() which
	// fully implements the Set-Cookie spec parsing. Fallback to body scan for
	// FortiGate firmwares that embed the token inline rather than in headers.
	for _, sc := range resp.Cookies() {
		if strings.EqualFold(sc.Name, "SVPNCOOKIE") && sc.Value != "" {
			c.cookie = sc.Value
			slog.Debug("SVPNCOOKIE extracted from Set-Cookie header")
			break
		}
	}
	if c.cookie == "" {
		if v := extractBodyCookie(bodyBytes); v != "" {
			c.cookie = v
			slog.Debug("SVPNCOOKIE extracted from response body")
		}
	}

	slog.Debug("httptunnel response",
		"method", method, "path", path,
		"status", resp.StatusCode,
		"cookie_set", c.cookie != "",
		"body", string(bodyBytes),
	)

	return &Response{
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       bodyBytes,
	}, nil
}

// SendRaw writes raw bytes to the TLS connection without reading a response.
// Used to activate tunnel mode (GET /remote/sslvpn-tunnel).
func (c *Client) SendRaw(data string) error {
	_, err := io.WriteString(c.conn, data)
	return err
}

// extractBodyCookie looks for "SVPNCOOKIE=<value>" in the response body.
// Some FortiGate firmwares return the session token this way instead of
// (or in addition to) a Set-Cookie header.
func extractBodyCookie(body []byte) string {
	const needle = "SVPNCOOKIE="
	idx := bytes.Index(bytes.ToUpper(body), []byte(needle))
	if idx == -1 {
		return ""
	}
	rest := body[idx+len(needle):]
	// Value ends at whitespace, semicolon, quote, or end of slice
	end := bytes.IndexAny(rest, " \t\r\n;\"'")
	if end == -1 {
		end = len(rest)
	}
	if end == 0 {
		return ""
	}
	return string(rest[:end])
}

