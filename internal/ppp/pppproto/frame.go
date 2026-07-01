// Package pppproto implements the small subset of PPP (RFC 1661), LCP and
// IPCP (RFC 1332/1877) negotiation needed to establish a FortiGate SSL-VPN
// tunnel where no system pppd is available (Windows). It is deliberately
// narrow: it negotiates just enough to reach the Opened state against a
// single, known peer (the FortiGate gateway), not a general-purpose PPP
// stack.
//
// Frames here are the same "raw PPP packet" byte layout already used
// elsewhere in this codebase (see internal/io/relay.go's extractIPCP): an
// optional 0xFF 0x03 address+control prefix, a 2-byte protocol field, then
// the protocol payload. This package is transport-agnostic — callers are
// responsible for HDLC framing and delivery.
package pppproto

import (
	"encoding/binary"
	"fmt"
)

// Protocol field values (RFC 1661 section 2, RFC 1332).
const (
	ProtoLCP  = 0xc021
	ProtoIPCP = 0x8021
	ProtoIPv4 = 0x0021
)

// LCP/IPCP codes (RFC 1661 section 5).
const (
	CodeConfigureRequest = 1
	CodeConfigureAck     = 2
	CodeConfigureNak     = 3
	CodeConfigureReject  = 4
	CodeTerminateRequest = 5
	CodeTerminateAck     = 6
	CodeCodeReject       = 7
	CodeProtocolReject   = 8 // LCP only
	CodeEchoRequest      = 9 // LCP only
	CodeEchoReply        = 10
	CodeDiscardRequest   = 11
)

// LCP option types (RFC 1661 section 6).
const (
	LCPOptMRU               = 1
	LCPOptACCM              = 2
	LCPOptAuthProtocol      = 3
	LCPOptMagicNumber       = 5
	LCPOptProtocolCompress  = 7
	LCPOptAddrCtrlCompress  = 8
)

// IPCP option types (RFC 1332 section 3, RFC 1877).
const (
	IPCPOptIPCompression = 2
	IPCPOptIPAddress     = 3
	IPCPOptPrimaryDNS    = 129
	IPCPOptSecondaryDNS  = 131
)

// Option is a single TLV option carried in a Configure-Request/Ack/Nak/Reject.
type Option struct {
	Type byte
	Data []byte
}

// Len returns the on-wire length of the option (2-byte header + data).
func (o Option) Len() int { return 2 + len(o.Data) }

// ConfigFrame is a Configure-Request/Ack/Nak/Reject frame: the four LCP/IPCP
// codes that carry a list of options.
type ConfigFrame struct {
	Code    byte
	ID      byte
	Options []Option
}

// Marshal encodes a ConfigFrame's protocol payload (code, id, length, options)
// — the protocol field itself is added by the caller (Send).
func (f ConfigFrame) Marshal() []byte {
	optLen := 0
	for _, o := range f.Options {
		optLen += o.Len()
	}
	buf := make([]byte, 4+optLen)
	buf[0] = f.Code
	buf[1] = f.ID
	binary.BigEndian.PutUint16(buf[2:4], uint16(4+optLen))
	off := 4
	for _, o := range f.Options {
		buf[off] = o.Type
		buf[off+1] = byte(o.Len())
		copy(buf[off+2:], o.Data)
		off += o.Len()
	}
	return buf
}

// ParseConfigFrame decodes a Configure-Request/Ack/Nak/Reject payload
// (everything after the 2-byte protocol field).
func ParseConfigFrame(payload []byte) (ConfigFrame, error) {
	if len(payload) < 4 {
		return ConfigFrame{}, fmt.Errorf("pppproto: frame too short (%d bytes)", len(payload))
	}
	f := ConfigFrame{Code: payload[0], ID: payload[1]}
	length := min(int(binary.BigEndian.Uint16(payload[2:4])), len(payload))
	i := 4
	for i+2 <= length {
		optType := payload[i]
		optLen := int(payload[i+1])
		if optLen < 2 || i+optLen > length {
			break
		}
		f.Options = append(f.Options, Option{Type: optType, Data: append([]byte(nil), payload[i+2:i+optLen]...)})
		i += optLen
	}
	return f, nil
}

// FindOption returns the first option of the given type, if present.
func (f ConfigFrame) FindOption(t byte) (Option, bool) {
	for _, o := range f.Options {
		if o.Type == t {
			return o, true
		}
	}
	return Option{}, false
}

// StripPrefix removes an optional leading 0xFF 0x03 (address+control) pair,
// matching the tolerance already used by internal/io/relay.go's extractIPCP.
func StripPrefix(pkt []byte) []byte {
	if len(pkt) >= 2 && pkt[0] == 0xFF && pkt[1] == 0x03 {
		return pkt[2:]
	}
	return pkt
}

// Protocol reads the 2-byte PPP protocol field from a packet, after
// optionally stripping the 0xFF 0x03 prefix. ok is false if the packet is
// too short to contain one.
func Protocol(pkt []byte) (proto uint16, rest []byte, ok bool) {
	pkt = StripPrefix(pkt)
	if len(pkt) < 2 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint16(pkt[0:2]), pkt[2:], true
}

// BuildFrame prepends the 0xFF 0x03 address+control prefix (matching pppd's
// noaccomp/nopcomp behavior, which this package always mirrors — see
// buildArgs in pppd_unix.go) and the 2-byte protocol field to a payload.
func BuildFrame(proto uint16, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = 0xFF
	out[1] = 0x03
	binary.BigEndian.PutUint16(out[2:4], proto)
	copy(out[4:], payload)
	return out
}
