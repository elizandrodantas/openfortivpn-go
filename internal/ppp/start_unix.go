//go:build !windows && !darwin

package ppp

import "github.com/elizandrodantas/openfortivpn-go/internal/config"

// Start launches the system pppd over a PTY.
func Start(cfg *config.Config) (Process, error) {
	return startPPPD(cfg)
}
