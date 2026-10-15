//go:build darwin

package ppp

import (
	"bytes"
	"testing"
)

func TestUtunHeaderRoundTrip(t *testing.T) {
	ip := []byte{0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4}
	framed := addUtunHeader(ip)
	if !bytes.Equal(framed[:utunHeaderLen], []byte{0, 0, 0, 2}) {
		t.Fatalf("header = % x, want AF_INET (00 00 00 02)", framed[:utunHeaderLen])
	}
	got, ok := stripUtunHeader(framed)
	if !ok || !bytes.Equal(got, ip) {
		t.Fatalf("stripUtunHeader = % x, %v; want % x, true", got, ok, ip)
	}
}

func TestStripUtunHeaderSkipsNonIPv4(t *testing.T) {
	ipv6 := []byte{0, 0, 0, 30, 0x60, 0, 0, 0} // AF_INET6 on darwin
	if _, ok := stripUtunHeader(ipv6); ok {
		t.Fatal("IPv6 packet should be skipped")
	}
	if _, ok := stripUtunHeader([]byte{0, 0, 0, 2}); ok {
		t.Fatal("header-only packet should be skipped")
	}
}
