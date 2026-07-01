package config

import (
	"bufio"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// LoadFile reads an INI-style config file and merges values into cfg.
// Lines starting with '#' are comments. Format: key = value (or key=value).
// Unknown keys return an error.
func LoadFile(cfg *Config, filename string) error {
	f, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("config: open %s: %w", filename, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx == -1 {
			return fmt.Errorf("config: %s:%d: missing '=' in %q", filename, lineNum, line)
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		if err := applyKey(cfg, key, val, filename, lineNum); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func applyKey(cfg *Config, key, val, filename string, line int) error {
	loc := func(msg string) error {
		return fmt.Errorf("config: %s:%d: %s: %q", filename, line, msg, val)
	}
	switch key {
	case "host":
		cfg.GatewayHost = val
	case "port":
		p, err := strconv.ParseUint(val, 10, 16)
		if err != nil || p < 1 || p > 65535 {
			return loc("invalid port")
		}
		cfg.GatewayPort = uint16(p)
	case "timeout":
		secs, err := strconv.ParseUint(val, 10, 32)
		if err != nil || secs == 0 {
			return loc("invalid timeout")
		}
		cfg.ConnectTimeout = time.Duration(secs) * time.Second
	case "username":
		cfg.Username = val
	case "password":
		cfg.Password = val
		cfg.PasswordSet = true
	case "otp":
		cfg.OTP = val
	case "otp-prompt":
		cfg.OTPPrompt = val
	case "otp-delay":
		d, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return loc("invalid otp-delay")
		}
		cfg.OTPDelay = time.Duration(d) * time.Second
	case "no-ftm-push":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid no-ftm-push")
		}
		cfg.NoFTMPush = b
	case "pinentry":
		cfg.Pinentry = val
	case "realm":
		cfg.Realm = val
	case "sni":
		cfg.SNI = val
	case "set-routes":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid set-routes")
		}
		cfg.SetRoutes = b
	case "set-dns":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid set-dns")
		}
		cfg.SetDNS = b
	case "half-internet-routes":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid half-internet-routes")
		}
		cfg.HalfInternetRoutes = b
	case "persistent":
		secs, err := strconv.ParseUint(val, 10, 32)
		if err != nil {
			return loc("invalid persistent")
		}
		cfg.Persistent = time.Duration(secs) * time.Second
	case "use-syslog":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid use-syslog")
		}
		cfg.UseSyslog = b
	case "use-resolvconf":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid use-resolvconf")
		}
		cfg.UseResolvconf = b
	case "pppd-use-peerdns":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid pppd-use-peerdns")
		}
		cfg.PPPDUsePeerDNS = b
	case "pppd-log":
		cfg.PPPDLog = val
	case "pppd-plugin":
		cfg.PPPDPlugin = val
	case "pppd-ipparam":
		cfg.PPPDIPParam = val
	case "pppd-ifname":
		cfg.PPPDIfname = val
	case "pppd-call":
		cfg.PPPDCall = val
	case "pppd-accept-remote":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid pppd-accept-remote")
		}
		cfg.PPPDAcceptRemote = b
	case "ppp-system":
		cfg.PPPSystem = val
	case "ca-file":
		cfg.CAFile = val
	case "user-cert":
		cfg.UserCert = val
		if strings.HasPrefix(val, "pkcs11:") {
			cfg.UseEngine = true
		}
	case "user-key":
		cfg.UserKey = val
	case "pem-passphrase":
		cfg.PEMPassphrase = val
		cfg.PEMPassSet = true
	case "insecure-ssl":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid insecure-ssl")
		}
		cfg.InsecureSSL = b
	case "min-tls":
		v, err := parseMinTLS(val)
		if err != nil {
			return loc("invalid min-tls")
		}
		cfg.MinTLS = v
	case "seclevel-1":
		b, err := parseBool(val)
		if err != nil {
			return loc("invalid seclevel-1")
		}
		cfg.Seclevel1 = b
	case "cipher-list":
		cfg.CipherList = val
	case "trusted-cert":
		if err := validateSHA256Hex(val); err != nil {
			return loc("invalid trusted-cert SHA-256 digest")
		}
		cfg.TrustedCerts = append(cfg.TrustedCerts, strings.ToLower(val))
	case "saml-login":
		p, err := strconv.ParseUint(val, 10, 16)
		if err != nil || p < 1 || p > 65535 {
			return loc("invalid saml-login port")
		}
		cfg.SAMLPort = uint16(p)
	case "user-agent":
		cfg.UserAgent = val
	case "hostcheck":
		cfg.Hostcheck = val
	case "check-virtual-desktop":
		cfg.CheckVirtualDesktop = val
	case "cookie", "cookie-on-stdin":
		// ignored in config file (security: only accepted via CLI)
	default:
		return fmt.Errorf("config: %s:%d: unknown key %q", filename, line, key)
	}
	return nil
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes":
		return true, nil
	case "0", "false", "no":
		return false, nil
	}
	return false, fmt.Errorf("not a boolean: %q", s)
}

func parseMinTLS(s string) (uint16, error) {
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
	return 0, fmt.Errorf("unknown TLS version %q", s)
}

func validateSHA256Hex(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("expected 64 hex chars, got %d", len(s))
	}
	_, err := hex.DecodeString(s)
	return err
}
