// Package hdlc implements HDLC-like framing for PPP packets per RFC 1662.
package hdlc

import "errors"

var (
	ErrBufferTooSmall = errors.New("hdlc: output buffer too small")
	ErrNoFrameFound   = errors.New("hdlc: no frame found in buffer")
	ErrInvalidFrame   = errors.New("hdlc: invalid frame")
	ErrBadChecksum    = errors.New("hdlc: bad frame checksum (FCS mismatch)")
)

// fcsTable is the lookup table used to calculate CRC-16 (from RFC 1662).
var fcsTable = [256]uint16{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
}

// addressControlChecksum is the precalculated FCS for the Address (0xFF) and
// Control (0x03) fields: frame_checksum_16bit(0xffff, {0xff, 0x03}, 2).
const addressControlChecksum uint16 = 0x3de3

func fcsUpdate(sum uint16, data []byte) uint16 {
	for _, b := range data {
		sum = (sum >> 8) ^ fcsTable[(sum^uint16(b))&0xff]
	}
	return sum
}

func inSendingACCM(b byte) bool {
	return b < 0x20 || (b&0x7f) == 0x7d || (b&0x7f) == 0x7e
}

func inReceivingACCM(b byte) bool {
	return b < 0x20
}

// Encoder wraps a PPP packet into HDLC frames. Each Encoder instance tracks
// whether a leading flag sequence (0x7E) is needed. Not safe for concurrent use.
type Encoder struct {
	needFlag bool
}

// NewEncoder returns an Encoder ready to encode the first frame (leading flag included).
func NewEncoder() *Encoder {
	return &Encoder{needFlag: true}
}

// Encode wraps packet into an HDLC frame and appends it to dst, returning the
// resulting slice. The caller may pass nil as dst to allocate a new buffer.
func (e *Encoder) Encode(dst, packet []byte) ([]byte, error) {
	// Worst case: flag + addr + esc+ctrl + 2*len(packet) + 2*2(fcs) + flag
	// We grow dst as needed.
	if e.needFlag {
		dst = append(dst, 0x7e)
	}

	// Address field (0xFF) — not escaped
	dst = append(dst, 0xff)
	// Control field (0x03) — always escaped
	dst = append(dst, 0x7d, 0x03^0x20)

	checksum := addressControlChecksum
	checksum = fcsUpdate(checksum, packet)

	for _, b := range packet {
		if inSendingACCM(b) {
			dst = append(dst, 0x7d, b^0x20)
		} else {
			dst = append(dst, b)
		}
	}

	// FCS (inverted, LSB first)
	checksum ^= 0xffff
	lo := byte(checksum & 0x00ff)
	hi := byte((checksum >> 8) & 0x00ff)
	if inSendingACCM(lo) {
		dst = append(dst, 0x7d, lo^0x20)
	} else {
		dst = append(dst, lo)
	}
	if inSendingACCM(hi) {
		dst = append(dst, 0x7d, hi^0x20)
	} else {
		dst = append(dst, hi)
	}

	dst = append(dst, 0x7e)
	e.needFlag = false
	return dst, nil
}

// Decoder decodes HDLC frames. Stateless — safe to share.
type Decoder struct{}

// FindFrame scans buf starting at offset *start and returns the position and
// length of the first complete HDLC frame (without surrounding 0x7E bytes).
// On success it updates *start to the frame's start offset.
// Returns ErrNoFrameFound if no complete frame exists yet.
func (Decoder) FindFrame(buf []byte, start *int) (frameStart, frameLen int, err error) {
	s := -1
	for i := *start; i < len(buf); i++ {
		if buf[i] == 0x7e {
			s = i + 1
			break
		}
	}
	if s == -1 {
		return 0, 0, ErrNoFrameFound
	}
	// Skip consecutive flag bytes (empty frames)
	for s < len(buf) && buf[s] == 0x7e {
		s++
	}
	e := -1
	for i := s; i < len(buf); i++ {
		if buf[i] == 0x7e {
			e = i
			break
		}
	}
	if e == -1 {
		return 0, 0, ErrNoFrameFound
	}
	*start = s
	return s, e - s, nil
}

// Decode extracts a PPP packet from an HDLC frame (without surrounding 0x7E
// bytes). Returns the decoded packet or an error.
func (Decoder) Decode(frame []byte) ([]byte, error) {
	if len(frame) < 5 {
		return nil, ErrInvalidFrame
	}

	start := 0
	hasAddrCtrl := false
	if frame[0] == 0xff && frame[1] == 0x7d && frame[2] == (0x03^0x20) {
		start = 3
		hasAddrCtrl = true
	}

	packet := make([]byte, 0, len(frame))
	inEscape := false
	for _, b := range frame[start:] {
		if b == 0x7d {
			if inEscape {
				return nil, ErrInvalidFrame
			}
			inEscape = true
			continue
		}
		if inEscape {
			b ^= 0x20
			inEscape = false
		} else if inReceivingACCM(b) {
			continue // drop characters possibly introduced by DCE
		}
		packet = append(packet, b)
	}
	if inEscape {
		return nil, ErrInvalidFrame
	}
	if len(packet) < 3 {
		return nil, ErrInvalidFrame
	}

	var checksum uint16
	if hasAddrCtrl {
		checksum = addressControlChecksum
	} else {
		checksum = 0xffff
	}
	checksum = fcsUpdate(checksum, packet)
	if checksum != 0xf0b8 {
		return nil, ErrBadChecksum
	}
	return packet[:len(packet)-2], nil
}
