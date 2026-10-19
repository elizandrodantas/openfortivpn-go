package pppproto

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// ErrPeerTerminated is returned by ServeLCP when the peer closes the link
// with an LCP Terminate-Request.
var ErrPeerTerminated = errors.New("pppproto: peer sent Terminate-Request")

// ServeLCP answers the peer's LCP traffic for the rest of the session, once
// NegotiateLCP has returned: Echo-Requests (keepalives), a Configure-Request
// that arrives after our own negotiation finished (a slow peer, or the peer
// renegotiating), and Terminate-Request. Without this, nothing reads those
// frames any more and the peer's side of LCP never reaches (or leaves)
// Opened — which is exactly what makes a gateway silently ignore IPCP.
//
// It returns ErrPeerTerminated when the peer terminates the link, or the
// link/context error when either ends.
func ServeLCP(ctx context.Context, link Link) error {
	for {
		pkt, err := link.Recv(ctx)
		if err != nil {
			return err
		}
		proto, payload, ok := Protocol(pkt)
		if !ok || proto != ProtoLCP || len(payload) < 1 {
			continue
		}
		switch payload[0] {
		case CodeConfigureRequest:
			cf, err := ParseConfigFrame(payload)
			if err != nil {
				continue
			}
			slog.Debug("pppproto: answering peer LCP Configure-Request after negotiation", "id", cf.ID)
			resp, _ := reviewPeerLCPRequest(cf)
			if err := link.Send(BuildFrame(ProtoLCP, resp.Marshal())); err != nil {
				return err
			}
		case CodeEchoRequest:
			if ef, ok := ParseEchoFrame(payload); ok {
				reply := EchoFrame{Code: CodeEchoReply, ID: ef.ID, Magic: ef.Magic}
				if err := link.Send(BuildFrame(ProtoLCP, reply.Marshal())); err != nil {
					return err
				}
			}
		case CodeTerminateRequest:
			if sf, ok := ParseSimpleFrame(payload); ok {
				ack := SimpleFrame{Code: CodeTerminateAck, ID: sf.ID}
				_ = link.Send(BuildFrame(ProtoLCP, ack.Marshal()))
			}
			return ErrPeerTerminated
		}
	}
}

// ServeIPCP answers IPCP Configure-Requests the peer sends after
// NegotiateIPCP has returned, so the peer's side of IPCP can still reach
// Opened if its request arrives late.
func ServeIPCP(ctx context.Context, link Link) error {
	for {
		pkt, err := link.Recv(ctx)
		if err != nil {
			return err
		}
		proto, payload, ok := Protocol(pkt)
		if !ok || proto != ProtoIPCP {
			continue
		}
		cf, err := ParseConfigFrame(payload)
		if err != nil || cf.Code != CodeConfigureRequest {
			continue
		}
		slog.Debug("pppproto: answering peer IPCP Configure-Request after negotiation", "id", cf.ID)
		resp, _ := reviewPeerIPCPRequest(cf)
		if err := link.Send(BuildFrame(ProtoIPCP, resp.Marshal())); err != nil {
			return err
		}
	}
}

// ProtocolReject builds a complete LCP Protocol-Reject packet (RFC 1661
// section 5.7) for a frame of an unsupported protocol: the rejected
// protocol number followed by the rejected frame's information field,
// truncated so the reply never exceeds maxLen bytes of LCP payload.
func ProtocolReject(id byte, rejected uint16, info []byte, maxLen int) []byte {
	const hdr = 4 + 2 // code, id, length, rejected-protocol
	if maxLen > hdr && len(info) > maxLen-hdr {
		info = info[:maxLen-hdr]
	}
	payload := make([]byte, hdr+len(info))
	payload[0] = CodeProtocolReject
	payload[1] = id
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(payload)))
	binary.BigEndian.PutUint16(payload[4:6], rejected)
	copy(payload[6:], info)
	return BuildFrame(ProtoLCP, payload)
}

var protoNames = map[uint16]string{
	ProtoLCP:  "LCP",
	ProtoIPCP: "IPCP",
	ProtoIPv4: "IPv4",
	0x80fd:    "CCP",
	0x8057:    "IPV6CP",
	0x0057:    "IPv6",
}

var codeNames = map[byte]string{
	CodeConfigureRequest: "ConfReq",
	CodeConfigureAck:     "ConfAck",
	CodeConfigureNak:     "ConfNak",
	CodeConfigureReject:  "ConfRej",
	CodeTerminateRequest: "TermReq",
	CodeTerminateAck:     "TermAck",
	CodeCodeReject:       "CodeRej",
	CodeProtocolReject:   "ProtRej",
	CodeEchoRequest:      "EchoReq",
	CodeEchoReply:        "EchoRep",
	CodeDiscardRequest:   "DiscardReq",
}

// Describe renders a raw PPP packet as a short, log-friendly summary,
// e.g. "LCP ConfReq id=1 data=0104054a".
func Describe(pkt []byte) string {
	proto, payload, ok := Protocol(pkt)
	if !ok {
		return fmt.Sprintf("short packet % x", pkt)
	}
	name, known := protoNames[proto]
	if !known {
		name = fmt.Sprintf("proto=%#04x", proto)
	}
	if proto == ProtoIPv4 || proto == 0x0057 || len(payload) < 4 {
		return fmt.Sprintf("%s len=%d", name, len(payload))
	}
	code, known := codeNames[payload[0]]
	if !known {
		code = fmt.Sprintf("code=%d", payload[0])
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s id=%d", name, code, payload[1])
	if len(payload) > 4 {
		fmt.Fprintf(&sb, " data=%x", payload[4:])
	}
	return sb.String()
}
