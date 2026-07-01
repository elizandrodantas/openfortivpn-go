package pppproto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
)

// LCPOptions configures our own outgoing LCP Configure-Request.
type LCPOptions struct {
	// MRU is the Maximum-Receive-Unit we propose (matches pppd's "mru 1354"
	// in pppd_unix.go). 0 omits the option.
	MRU int
}

// NegotiateLCP drives LCP to the Opened state against a single peer: our own
// Configure-Request must be Acked, and the peer's Configure-Request must be
// Acked by us. It intentionally never negotiates authentication, protocol
// field compression (PFC) or address/control field compression (ACFC) —
// matching pppd's "noauth noaccomp nopcomp" flags used on Unix — by
// rejecting those options if the peer proposes them for its own frames.
//
// Any LCP Echo-Request seen during negotiation is answered immediately so an
// impatient peer doesn't give up while we're still negotiating.
func NegotiateLCP(ctx context.Context, link Link, opts LCPOptions) error {
	ctx, cancel := context.WithTimeout(ctx, NegotiateTimeout)
	defer cancel()

	id := byte(1)
	send := func() error {
		return link.Send(BuildFrame(ProtoLCP, buildLCPRequest(id, opts).Marshal()))
	}
	if err := send(); err != nil {
		return fmt.Errorf("pppproto: LCP: %w", err)
	}

	var weAckedPeer, peerAckedUs bool
	retries := 0
	for !weAckedPeer || !peerAckedUs {
		pkt, err := link.Recv(ctx)
		if err != nil {
			return fmt.Errorf("pppproto: LCP negotiation: %w", err)
		}
		proto, payload, ok := Protocol(pkt)
		if !ok || proto != ProtoLCP {
			continue // not LCP — ignore during negotiation
		}
		cf, err := ParseConfigFrame(payload)
		if err != nil {
			continue
		}

		switch cf.Code {
		case CodeConfigureRequest:
			resp, rejected := reviewPeerLCPRequest(cf)
			if err := link.Send(BuildFrame(ProtoLCP, resp.Marshal())); err != nil {
				return fmt.Errorf("pppproto: LCP: %w", err)
			}
			if !rejected {
				weAckedPeer = true
			}
			// If we rejected something, the peer is expected to resend a
			// corrected Configure-Request; loop and wait for it.

		case CodeConfigureAck:
			if cf.ID == id {
				peerAckedUs = true
			}

		case CodeConfigureNak, CodeConfigureReject:
			if cf.ID != id {
				continue
			}
			retries++
			if retries > maxConfigureRetries {
				return errors.New("pppproto: LCP negotiation did not converge")
			}
			applyLCPFeedback(&opts, cf, cf.Code == CodeConfigureReject)
			id++
			if err := send(); err != nil {
				return fmt.Errorf("pppproto: LCP: %w", err)
			}

		case CodeEchoRequest:
			if ef, ok := ParseEchoFrame(payload); ok {
				reply := EchoFrame{Code: CodeEchoReply, ID: ef.ID, Magic: ef.Magic}
				_ = link.Send(BuildFrame(ProtoLCP, reply.Marshal()))
			}
		}
	}
	return nil
}

// buildLCPRequest constructs our outgoing Configure-Request options.
func buildLCPRequest(id byte, opts LCPOptions) ConfigFrame {
	cf := ConfigFrame{Code: CodeConfigureRequest, ID: id}
	if opts.MRU > 0 {
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(opts.MRU))
		cf.Options = append(cf.Options, Option{Type: LCPOptMRU, Data: b})
	}
	return cf
}

// reviewPeerLCPRequest decides how to answer the peer's own Configure-Request.
// We accept MRU/ACCM/Magic-Number as proposed (our HDLC encoder already
// escapes every control byte regardless of any negotiated ACCM, so any ACCM
// value the peer proposes for our outgoing frames is safe to accept), and
// reject anything implying authentication or field compression, since we
// implement neither.
func reviewPeerLCPRequest(cf ConfigFrame) (resp ConfigFrame, rejected bool) {
	var reject []Option
	for _, o := range cf.Options {
		switch o.Type {
		case LCPOptMRU, LCPOptACCM, LCPOptMagicNumber:
			// acceptable as-is
		default:
			reject = append(reject, o)
		}
	}
	if len(reject) > 0 {
		return ConfigFrame{Code: CodeConfigureReject, ID: cf.ID, Options: reject}, true
	}
	return ConfigFrame{Code: CodeConfigureAck, ID: cf.ID, Options: cf.Options}, false
}

// applyLCPFeedback adjusts our proposed options after a Nak (adopt the
// suggested value) or Reject (drop the option) of our own Configure-Request.
func applyLCPFeedback(opts *LCPOptions, cf ConfigFrame, isReject bool) {
	for _, o := range cf.Options {
		if o.Type != LCPOptMRU {
			continue
		}
		if isReject {
			opts.MRU = 0
		} else if len(o.Data) == 2 {
			opts.MRU = int(binary.BigEndian.Uint16(o.Data))
		}
	}
}
