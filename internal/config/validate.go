package config

import "fmt"

// Validate checks that the config has the minimum required fields to attempt
// a VPN connection.
func Validate(cfg *Config) error {
	if cfg.GatewayHost == "" {
		return fmt.Errorf("config: gateway host is required")
	}
	if cfg.GatewayPort == 0 {
		return fmt.Errorf("config: gateway port is required")
	}
	// Cookie-based auth needs no username/password
	if cfg.Cookie == "" && cfg.SAMLPort == 0 && cfg.UserCert == "" {
		if cfg.Username == "" {
			return fmt.Errorf("config: username is required (or provide --cookie / --saml-login / --user-cert)")
		}
	}
	for _, digest := range cfg.TrustedCerts {
		if err := validateSHA256Hex(digest); err != nil {
			return fmt.Errorf("config: invalid trusted-cert %q: %w", digest, err)
		}
	}
	return nil
}
