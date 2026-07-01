package httptunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
)

// ServeSAML starts a local HTTP server on the given port that waits for the
// FortiGate SAML redirect callback. It extracts the session ID from the
// ?id= query parameter and sends it on the returned channel, then shuts down.
//
// The caller should log the SAML login URL and open it in a browser.
func ServeSAML(ctx context.Context, port uint16) (<-chan string, error) {
	ch := make(chan string, 1)

	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("httptunnel: SAML listen on port %d: %w", port, err)
	}

	mux := http.NewServeMux()
	srv := &http.Server{Handler: mux}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if id == "" {
			// Strip from cookie header as fallback
			for _, c := range r.Cookies() {
				if c.Name == "samlSessionId" {
					id = c.Value
					break
				}
			}
		}
		if id == "" {
			// Extract from fragment or form field
			r.ParseForm() //nolint:errcheck
			id = r.FormValue("id")
		}
		if id == "" {
			http.Error(w, "missing id parameter", http.StatusBadRequest)
			return
		}
		slog.Info("SAML session received", "id", truncate(id, 20))
		fmt.Fprintln(w, "<html><body>Login successful. You may close this window.</body></html>")
		select {
		case ch <- id:
		default:
		}
		go srv.Shutdown(context.Background()) //nolint:errcheck
	})

	go func() {
		srv.Serve(listener) //nolint:errcheck
	}()
	go func() {
		<-ctx.Done()
		srv.Shutdown(context.Background()) //nolint:errcheck
	}()

	return ch, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// SAMLLoginURL returns the URL the user must visit to initiate SAML login.
func SAMLLoginURL(gatewayHost string, gatewayPort uint16, samlPort uint16) string {
	host := fmt.Sprintf("%s:%d", gatewayHost, gatewayPort)
	callback := fmt.Sprintf("http://127.0.0.1:%d/", samlPort)
	return fmt.Sprintf("https://%s/remote/saml/start?redirect=1&redirect_url=%s",
		host, strings.ReplaceAll(callback, ":", "%3A"))
}
