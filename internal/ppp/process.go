// Package ppp implements PPP tunnel management: either by launching the
// system pppd over a PTY (pppd_unix.go), or by negotiating LCP/IPCP itself
// and relaying IPv4 over a virtual TUN device (engine.go).
package ppp

import (
	"context"
	"io"
)

// Process is a running PPP session, whichever backend drives it.
type Process interface {
	// PTY returns the local PPP transport used by internal/io.RunLoop: an
	// HDLC-framed, full-duplex byte stream.
	PTY() io.ReadWriter
	// Wait waits for the session to end, respecting context cancellation.
	Wait(ctx context.Context) error
	// Close tears the session down. Safe to call multiple times.
	Close()
}
