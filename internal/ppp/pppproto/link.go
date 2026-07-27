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

// retransmitter tracks when the next Configure-Request retransmission is
// due, across an entire negotiation — not per receive attempt. This matters:
// a naive "wait RestartInterval, retransmit" reset on every call would never
// fire if the peer sends anything at all more often than RestartInterval
// (an Echo-Request keepalive, a frame for a different protocol, a late LCP
// Configure-Request during IPCP negotiation) — the deadline would keep
// getting silently pushed out by unrelated traffic, and a genuinely
// unanswered request would just sit there until NegotiateTimeout with zero
// retransmissions ever sent. Retries is a pointer so Nak/Reject-triggered
// retransmissions (handled by the caller, which also resends) share the
// same budget and correctly push the next deadline out too.
type retransmitter struct {
	next    time.Time
	retries *int
	send    func() error
}

func newRetransmitter(retries *int, send func() error) *retransmitter {
	return &retransmitter{next: time.Now().Add(RestartInterval), retries: retries, send: send}
}

// recv waits for the next packet up to the current retransmit deadline. If
// the deadline passes with nothing received, it retransmits and extends the
// deadline; receiving (and the caller ignoring) an irrelevant packet does
// not reset it.
func (r *retransmitter) recv(ctx context.Context, link Link) ([]byte, error) {
	for {
		recvCtx, cancel := context.WithDeadline(ctx, r.next)
		pkt, err := link.Recv(recvCtx)
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
		*r.retries++
		if *r.retries > maxConfigureRetries {
			return nil, errors.New("no response from peer after repeated retransmissions")
		}
		if err := r.send(); err != nil {
			return nil, err
		}
		r.next = time.Now().Add(RestartInterval)
	}
}

// resendNow retransmits immediately (e.g. after adjusting options in
// response to a Nak/Reject) and pushes the retransmit deadline back out,
// so an imminent timeout-triggered retransmit doesn't immediately follow
// with the same content.
func (r *retransmitter) resendNow() error {
	if err := r.send(); err != nil {
		return err
	}
	r.next = time.Now().Add(RestartInterval)
	return nil
}
