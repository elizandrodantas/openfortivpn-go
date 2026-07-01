package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/tunnel"
	"github.com/elizandrodantas/openfortivpn-go/pkg/version"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	var (
		cfgFile string
		cfg     = config.Defaults()
		verbose int
		quiet   bool
		logFile string

		// Flags that map to cfg fields
		host        string
		port        uint16
		timeout     uint
		username    string
		password    string
		otp         string
		cookie      string
		samlLogin   uint16
		realm       string
		sni         string
		ifname      string
		pinentry    string
		caFile      string
		userCert    string
		userKey     string
		pemPass     string
		insecure    bool
		minTLS      string
		seclevel1   bool
		cipherList  string
		trustedCert []string
		persistent  uint

		noRoutes        bool
		noDNS           bool
		halfInternet    bool
		pppdUsePeerDNS  bool
		pppdLog         string
		pppdPlugin      string
		pppdIfname      string
		pppdCall        string
		pppdAcceptRemote bool
	)

	cmd := &cobra.Command{
		Use:          "openfortivpn [host[:port]]",
		Short:        "FortiGate SSL VPN client",
		Version:      version.Version,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true, // only print usage on --help, not on runtime errors
		RunE: func(cmd *cobra.Command, args []string) error {
			// Setup structured logging
			level := slog.LevelInfo
			if quiet {
				level = slog.LevelError
			} else if verbose >= 3 {
				level = slog.Level(-12) // DEBUG_ALL
			} else if verbose == 2 {
				level = slog.Level(-8) // DEBUG_DETAILS
			} else if verbose == 1 {
				level = slog.LevelDebug
			}

			var logWriter io.Writer = os.Stderr
			if logFile != "" {
				f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					return fmt.Errorf("open log file: %w", err)
				}
				defer f.Close()
				// Tee: stderr (filtered by level) + file (always DEBUG)
				stderrHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
				fileHandler := slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug - 12})
				slog.SetDefault(slog.New(&multiHandler{handlers: []slog.Handler{stderrHandler, fileHandler}}))
				_ = logWriter
			} else {
				handler := slog.NewTextHandler(logWriter, &slog.HandlerOptions{Level: level})
				slog.SetDefault(slog.New(handler))
			}

			// Load config file if specified (or default path)
			if cfgFile == "" {
				cfgFile = "/etc/openfortivpn/config"
			}
			if err := config.LoadFile(cfg, cfgFile); err != nil && !os.IsNotExist(err) {
				slog.Warn("could not load config file", "file", cfgFile, "err", err)
			}

			// Apply CLI flags (override config file)
			if len(args) > 0 {
				h, p, err := parseHostPort(args[0])
				if err != nil {
					return err
				}
				if h != "" {
					cfg.GatewayHost = h
				}
				if p != 0 {
					cfg.GatewayPort = p
				}
			}
			applyStringFlag(cmd, "host", host, &cfg.GatewayHost)
			applyUint16Flag(cmd, "port", port, &cfg.GatewayPort)
			if cmd.Flags().Changed("timeout") {
				cfg.ConnectTimeout = config.SecondsToD(timeout)
			}
			applyStringFlag(cmd, "username", username, &cfg.Username)
			if cmd.Flags().Changed("password") {
				cfg.Password = password
				cfg.PasswordSet = true
			}
			applyStringFlag(cmd, "otp", otp, &cfg.OTP)
			applyStringFlag(cmd, "cookie", cookie, &cfg.Cookie)
			applyUint16Flag(cmd, "saml-login", samlLogin, &cfg.SAMLPort)
			applyStringFlag(cmd, "realm", realm, &cfg.Realm)
			applyStringFlag(cmd, "sni", sni, &cfg.SNI)
			applyStringFlag(cmd, "ifname", ifname, &cfg.IfaceName)
			applyStringFlag(cmd, "pinentry", pinentry, &cfg.Pinentry)
			applyStringFlag(cmd, "ca-file", caFile, &cfg.CAFile)
			applyStringFlag(cmd, "user-cert", userCert, &cfg.UserCert)
			applyStringFlag(cmd, "user-key", userKey, &cfg.UserKey)
			if cmd.Flags().Changed("pem-passphrase") {
				cfg.PEMPassphrase = pemPass
				cfg.PEMPassSet = true
			}
			if cmd.Flags().Changed("insecure-ssl") {
				cfg.InsecureSSL = insecure
			}
			if cmd.Flags().Changed("min-tls") {
				v, err := parseTLSVersion(minTLS)
				if err != nil {
					return err
				}
				cfg.MinTLS = v
			}
			if cmd.Flags().Changed("seclevel-1") {
				cfg.Seclevel1 = seclevel1
			}
			applyStringFlag(cmd, "cipher-list", cipherList, &cfg.CipherList)
			if len(trustedCert) > 0 {
				cfg.TrustedCerts = append(cfg.TrustedCerts, trustedCert...)
			}
			if cmd.Flags().Changed("no-routes") && noRoutes {
				cfg.SetRoutes = false
			}
			if cmd.Flags().Changed("no-dns") && noDNS {
				cfg.SetDNS = false
			}
			if cmd.Flags().Changed("half-internet-routes") {
				cfg.HalfInternetRoutes = halfInternet
			}
			if cmd.Flags().Changed("pppd-use-peerdns") {
				cfg.PPPDUsePeerDNS = pppdUsePeerDNS
			}
			applyStringFlag(cmd, "pppd-log", pppdLog, &cfg.PPPDLog)
			applyStringFlag(cmd, "pppd-plugin", pppdPlugin, &cfg.PPPDPlugin)
			applyStringFlag(cmd, "pppd-ifname", pppdIfname, &cfg.PPPDIfname)
			applyStringFlag(cmd, "pppd-call", pppdCall, &cfg.PPPDCall)
			if cmd.Flags().Changed("pppd-accept-remote") {
				cfg.PPPDAcceptRemote = pppdAcceptRemote
			}
			if cmd.Flags().Changed("persistent") {
				cfg.Persistent = 0
				if persistent > 0 {
					cfg.Persistent = config.SecondsToD(persistent)
				}
			}

			if err := config.Validate(cfg); err != nil {
				return err
			}

			// Handle OS signals for clean shutdown
			ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()

			slog.Info("openfortivpn-go starting", "version", version.Version)
			return tunnel.Run(ctx, cfg)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&cfgFile, "config", "c", "", "Config file path (default: /etc/openfortivpn/config)")
	f.CountVarP(&verbose, "verbose", "v", "Increase verbosity (-v, -vv, -vvv)")
	f.BoolVarP(&quiet, "quiet", "q", false, "Suppress non-error output")
	f.StringVar(&host, "host", "", "VPN gateway hostname")
	f.Uint16Var(&port, "port", 0, "VPN gateway port")
	f.UintVar(&timeout, "timeout", 0, "Connect timeout in seconds (default 20)")
	f.StringVarP(&username, "username", "u", "", "Username")
	f.StringVarP(&password, "password", "p", "", "Password")
	f.StringVar(&otp, "otp", "", "One-time password")
	f.StringVar(&cookie, "cookie", "", "SVPNCOOKIE session cookie")
	f.Uint16Var(&samlLogin, "saml-login", 0, "Enable SAML login on given port (e.g. 8020)")
	f.StringVar(&realm, "realm", "", "Authentication realm")
	f.StringVar(&sni, "sni", "", "TLS SNI hostname override")
	f.StringVar(&ifname, "ifname", "", "Bind to network interface")
	f.StringVar(&pinentry, "pinentry", "", "Path to pinentry binary for secure password input")
	f.StringVar(&caFile, "ca-file", "", "CA certificate file")
	f.StringVar(&userCert, "user-cert", "", "Client certificate file (PEM or pkcs11: URI)")
	f.StringVar(&userKey, "user-key", "", "Client private key file")
	f.StringVar(&pemPass, "pem-passphrase", "", "Passphrase for encrypted private key")
	f.BoolVar(&insecure, "insecure-ssl", false, "Allow weak/invalid TLS (dangerous)")
	f.StringVar(&minTLS, "min-tls", "", "Minimum TLS version (1.0, 1.1, 1.2, 1.3)")
	f.BoolVar(&seclevel1, "seclevel-1", false, "Use OpenSSL SECLEVEL=1 for weak DH params")
	f.StringVar(&cipherList, "cipher-list", "", "TLS cipher list")
	f.StringArrayVar(&trustedCert, "trusted-cert", nil, "Trusted certificate SHA-256 digest (repeatable)")
	f.BoolVar(&noRoutes, "no-routes", false, "Do not modify routing table")
	f.BoolVar(&noDNS, "no-dns", false, "Do not modify DNS configuration")
	f.BoolVar(&halfInternet, "half-internet-routes", false, "Use 0.0.0.0/1 + 128.0.0.0/1 instead of default route")
	f.BoolVar(&pppdUsePeerDNS, "pppd-use-peerdns", false, "Ask pppd to configure DNS")
	f.StringVar(&pppdLog, "pppd-log", "", "pppd log file")
	f.StringVar(&pppdPlugin, "pppd-plugin", "", "pppd plugin path")
	f.StringVar(&pppdIfname, "pppd-ifname", "", "pppd interface name")
	f.StringVar(&pppdCall, "pppd-call", "", "pppd call file")
	f.BoolVar(&pppdAcceptRemote, "pppd-accept-remote", false, "Accept remote IP from pppd")
	f.UintVar(&persistent, "persistent", 0, "Reconnect interval in seconds (0 = no reconnect)")
	f.StringVar(&logFile, "log-file", "", "Write all logs (DEBUG level) to this file, regardless of -v")

	return cmd
}

func parseHostPort(s string) (string, uint16, error) {
	h, p, err := splitHostPort(s)
	if err != nil {
		return s, 0, nil // treat whole string as host
	}
	var port uint16
	if p != "" {
		var n int
		fmt.Sscanf(p, "%d", &n)
		if n < 1 || n > 65535 {
			return "", 0, fmt.Errorf("invalid port: %s", p)
		}
		port = uint16(n)
	}
	return h, port, nil
}

func splitHostPort(s string) (string, string, error) {
	// Simple split on last ':' for IPv4; proper impl would handle IPv6 [::1]:8443
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == ':' {
			return s[:i], s[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no port")
}

func parseTLSVersion(s string) (uint16, error) {
	switch s {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	}
	return 0, fmt.Errorf("unknown TLS version %q (use 1.0, 1.1, 1.2, or 1.3)", s)
}

func applyStringFlag(cmd *cobra.Command, name, val string, dst *string) {
	if cmd.Flags().Changed(name) {
		*dst = val
	}
}

func applyUint16Flag(cmd *cobra.Command, name string, val uint16, dst *uint16) {
	if cmd.Flags().Changed(name) {
		*dst = val
	}
}

// multiHandler fans out slog records to multiple handlers.
type multiHandler struct {
	handlers []slog.Handler
}

func (m *multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m *multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

func (m *multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithAttrs(attrs)
	}
	return &multiHandler{handlers: hs}
}

func (m *multiHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		hs[i] = h.WithGroup(name)
	}
	return &multiHandler{handlers: hs}
}
