// Package io implements the I/O relay loop and PPP-over-TLS packet framing.
package io

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PPP-over-TLS 6-byte header magic as sent by the FortiGate gateway.
const pppMagic uint16 = 0x5050

var (
	ErrBadHeader      = errors.New("io: bad PPP-over-TLS packet header")
	ErrHTTPResponse   = errors.New("io: gateway returned HTTP response (tunnel mode not enabled)")
)

// ReadPacket reads one PPP packet from r. The packet is preceded by a 6-byte
// FortiGate header: [total_hi][total_lo][0x50][0x50][size_hi][size_lo].
func ReadPacket(r io.Reader) ([]byte, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("io: reading packet header: %w", err)
	}

	// Detect HTTP response from gateway (tunnel not yet activated)
	if hdr[0] == 'H' && hdr[1] == 'T' && hdr[2] == 'T' && hdr[3] == 'P' {
		return nil, ErrHTTPResponse
	}

	total := binary.BigEndian.Uint16(hdr[0:2])
	magic := binary.BigEndian.Uint16(hdr[2:4])
	size := binary.BigEndian.Uint16(hdr[4:6])

	if magic != pppMagic || total < 7 || uint16(total)-6 != size {
		return nil, fmt.Errorf("%w: magic=0x%04x total=%d size=%d", ErrBadHeader, magic, total, size)
	}

	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("io: reading packet payload: %w", err)
	}
	return payload, nil
}

// WritePacket prepends the 6-byte FortiGate header to payload and writes it to w.
func WritePacket(w io.Writer, payload []byte) error {
	size := uint16(len(payload))
	total := 6 + size
	hdr := [6]byte{
		byte(total >> 8), byte(total),
		0x50, 0x50,
		byte(size >> 8), byte(size),
	}
	buf := make([]byte, 6+len(payload))
	copy(buf[:6], hdr[:])
	copy(buf[6:], payload)
	_, err := w.Write(buf)
	return err
}
