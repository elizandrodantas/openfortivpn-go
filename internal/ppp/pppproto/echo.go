package pppproto

import "encoding/binary"

// EchoFrame is an LCP Echo-Request/Echo-Reply or Terminate-Request/Ack
// payload: Code(1) ID(1) Length(2) [Magic-Number(4)] Data(...). Terminate
// frames carry no magic number field; callers that don't need one can leave
// Magic at 0 and treat the wire format as Code/ID/Length/Data.
type EchoFrame struct {
	Code  byte
	ID    byte
	Magic uint32
	Data  []byte
}

// ParseEchoFrame decodes an Echo-Request/Reply payload (magic number present).
func ParseEchoFrame(payload []byte) (EchoFrame, bool) {
	if len(payload) < 8 {
		return EchoFrame{}, false
	}
	length := min(int(binary.BigEndian.Uint16(payload[2:4])), len(payload))
	if length < 8 {
		return EchoFrame{}, false
	}
	return EchoFrame{
		Code:  payload[0],
		ID:    payload[1],
		Magic: binary.BigEndian.Uint32(payload[4:8]),
		Data:  append([]byte(nil), payload[8:length]...),
	}, true
}

// Marshal encodes an Echo-Request/Reply frame (with magic number).
func (f EchoFrame) Marshal() []byte {
	buf := make([]byte, 8+len(f.Data))
	buf[0] = f.Code
	buf[1] = f.ID
	binary.BigEndian.PutUint16(buf[2:4], uint16(8+len(f.Data)))
	binary.BigEndian.PutUint32(buf[4:8], f.Magic)
	copy(buf[8:], f.Data)
	return buf
}

// SimpleFrame is a Terminate-Request/Ack/Code-Reject payload with no magic
// number: Code(1) ID(1) Length(2) Data(...).
type SimpleFrame struct {
	Code byte
	ID   byte
	Data []byte
}

// ParseSimpleFrame decodes a Terminate-Request/Ack payload.
func ParseSimpleFrame(payload []byte) (SimpleFrame, bool) {
	if len(payload) < 4 {
		return SimpleFrame{}, false
	}
	length := min(int(binary.BigEndian.Uint16(payload[2:4])), len(payload))
	return SimpleFrame{
		Code: payload[0],
		ID:   payload[1],
		Data: append([]byte(nil), payload[4:length]...),
	}, true
}

// Marshal encodes a Terminate-Request/Ack frame.
func (f SimpleFrame) Marshal() []byte {
	buf := make([]byte, 4+len(f.Data))
	buf[0] = f.Code
	buf[1] = f.ID
	binary.BigEndian.PutUint16(buf[2:4], uint16(4+len(f.Data)))
	copy(buf[4:], f.Data)
	return buf
}
