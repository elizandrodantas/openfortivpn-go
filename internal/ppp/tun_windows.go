//go:build windows

// Package ppp implements PPP tunnel management. On Windows, there is no pppd
// daemon available, so we use a wintun virtual TUN interface and implement
// PPP/IPCP negotiation in pure Go.
package ppp

import (
	"context"
	"fmt"
	"os"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
)

// Process wraps a virtual TUN interface used as the PPP transport on Windows.
// This is a stub implementation — full PPP/IPCP stack in Go is required.
type Process struct {
	tunFd *os.File
}

// PTY returns a file descriptor representing the TUN interface I/O.
// On Windows this is a pipe connected to the wintun adapter.
func (p *Process) PTY() *os.File {
	return p.tunFd
}

// Start creates a wintun TUN adapter and starts PPP/IPCP negotiation.
// Requires Administrator privileges.
func Start(cfg *config.Config) (*Process, error) {
	// TODO: integrate golang.zx2c4.com/wintun for TUN adapter creation.
	// The PPP/IPCP state machine (Configure-Request/ACK/NAK) must be
	// implemented in Go since pppd is not available on Windows.
	return nil, fmt.Errorf("ppp: Windows TUN support not yet implemented; " +
		"contribute at https://github.com/elizandrodantas/openfortivpn-go")
}

// Wait waits for the TUN session to end.
func (p *Process) Wait(_ context.Context) error {
	return nil
}

// Close closes the TUN adapter.
func (p *Process) Close() {
	if p.tunFd != nil {
		p.tunFd.Close()
	}
}
