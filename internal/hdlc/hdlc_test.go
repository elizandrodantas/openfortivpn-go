package hdlc

import (
	"bytes"
	"testing"
)

func TestEncodeDecode_RoundTrip(t *testing.T) {
	cases := [][]byte{
		{0x80, 0x21, 0x01, 0x01, 0x00, 0x04},                   // IPCP Config-Request
		{0xc0, 0x21, 0x01, 0x00, 0x00, 0x04},                   // LCP Config-Request
		{0x00, 0x21, 0x45, 0x00, 0x00, 0x3c, 0x00, 0x01},       // IP packet fragment
		bytes.Repeat([]byte{0x7e, 0x7d, 0x00, 0xff, 0x1f}, 20), // lots of special bytes
	}

	dec := Decoder{}

	for _, pkt := range cases {
		// Each packet is encoded independently: use a fresh encoder so
		// the leading flag sequence (0x7E) is always present.
		enc := NewEncoder()
		frame, err := enc.Encode(nil, pkt)
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		start := 0
		s, n, err := dec.FindFrame(frame, &start)
		if err != nil {
			t.Fatalf("FindFrame failed: %v", err)
		}

		got, err := dec.Decode(frame[s : s+n])
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if !bytes.Equal(got, pkt) {
			t.Errorf("round-trip mismatch:\n  want %x\n  got  %x", pkt, got)
		}
	}
}

func TestEncoder_FirstFrameHasLeadingFlag(t *testing.T) {
	enc := NewEncoder()
	frame, _ := enc.Encode(nil, []byte{0x01, 0x02})
	if frame[0] != 0x7e {
		t.Errorf("first frame should start with 0x7e flag, got 0x%02x", frame[0])
	}
}

func TestEncoder_SubsequentFramesNoLeadingFlag(t *testing.T) {
	enc := NewEncoder()
	enc.Encode(nil, []byte{0x01}) //nolint first frame
	frame, _ := enc.Encode(nil, []byte{0x02})
	// The previous frame ends with 0x7e which serves as delimiter for next
	if frame[0] == 0x7e {
		t.Errorf("second frame should not start with extra 0x7e flag")
	}
}

func TestDecode_BadChecksum(t *testing.T) {
	enc := NewEncoder()
	frame, _ := enc.Encode(nil, []byte{0x80, 0x21, 0x01, 0x01, 0x00, 0x04})

	start := 0
	dec := Decoder{}
	s, n, _ := dec.FindFrame(frame, &start)

	// Corrupt a byte in the middle of the frame
	corrupt := make([]byte, n)
	copy(corrupt, frame[s:s+n])
	corrupt[n/2] ^= 0xff

	_, err := dec.Decode(corrupt)
	if err != ErrBadChecksum {
		t.Errorf("expected ErrBadChecksum, got %v", err)
	}
}

func TestDecode_InvalidFrame(t *testing.T) {
	dec := Decoder{}
	_, err := dec.Decode([]byte{0x01, 0x02})
	if err != ErrInvalidFrame {
		t.Errorf("expected ErrInvalidFrame for short frame, got %v", err)
	}
}

func TestFindFrame_NoFrame(t *testing.T) {
	dec := Decoder{}
	start := 0
	_, _, err := dec.FindFrame([]byte{0x01, 0x02, 0x03}, &start)
	if err != ErrNoFrameFound {
		t.Errorf("expected ErrNoFrameFound, got %v", err)
	}
}
