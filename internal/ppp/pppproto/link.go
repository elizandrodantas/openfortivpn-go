package pppproto

import (
	"context"
	"errors"
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
const NegotiateTimeout = 60 * time.Second

// RestartInterval is how long we wait for any response before retransmitting
// our current Configure-Request unchanged — matching pppd's default
// "lcp-restart" timer (RFC 1661's LCP FSM is retransmission-based, not
// send-once-and-wait: a lost or delayed first reply is expected and normal,
// not a fatal condition).
const RestartInterval = 3 * time.Second

// maxConfigureRetries bounds how many Configure-Request retransmissions we
// send (whether triggered by RestartInterval elapsing with no response, or
// by an explicit Nak/Reject requiring adjusted options) before giving up on
// a negotiation that isn't converging. At one retry per RestartInterval,
// this spans the bulk of NegotiateTimeout.
const maxConfigureRetries = 20

// recvOrRetransmit waits for the next packet, retransmitting the current
// Configure-Request (via send, unchanged) if nothing arrives within
// RestartInterval — see NegotiateLCP's doc comment for why this matters.
// retries is shared with the caller's Nak/Reject-triggered retransmission
// counter so both are bounded by the same budget.
func recvOrRetransmit(ctx context.Context, link Link, retries *int, send func() error) ([]byte, error) {
	for {
		waitCtx, cancel := context.WithTimeout(ctx, RestartInterval)
		pkt, err := link.Recv(waitCtx)
		cancel()
		if err == nil {
			return pkt, nil
		}
		if ctx.Err() != nil {
			return nil, ctx.Err() // overall negotiation deadline or cancellation
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return nil, err // a real failure (e.g. link closed), not a retransmit signal
		}
		*retries++
		if *retries > maxConfigureRetries {
			return nil, errors.New("no response from peer after repeated retransmissions")
		}
		if err := send(); err != nil {
			return nil, err
		}
	}
}
