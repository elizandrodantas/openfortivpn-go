package pppproto

import (
	"context"
	"time"
)

// Link is the transport a Negotiate* function speaks over: raw PPP packets
// (0xFF 0x03 prefix + 2-byte protocol field + payload), with framing and
// delivery handled by the caller.
type Link interface {
	// Send transmits one raw PPP packet.
	Send(pkt []byte) error
	// Recv blocks for the next raw PPP packet, or returns ctx.Err() if ctx
	// is done first.
	Recv(ctx context.Context) ([]byte, error)
}

// NegotiateTimeout bounds how long LCP or IPCP negotiation may run before
// giving up — without it, a non-responsive or confused peer would hang the
// tunnel indefinitely with no feedback (the same failure mode fixed for the
// initial TCP/TLS connect in internal/tlsconn).
const NegotiateTimeout = 30 * time.Second

// maxConfigureRetries bounds how many Configure-Request retransmissions we
// send before giving up on a negotiation that isn't converging.
const maxConfigureRetries = 10
