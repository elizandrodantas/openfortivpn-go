package pppproto

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

// parseSent decodes one packet our side sent, failing the test on garbage.
func parseSent(t *testing.T, pkt []byte, wantProto uint16) ConfigFrame {
	t.Helper()
	proto, payload, ok := Protocol(pkt)
	if !ok || proto != wantProto {
		t.Fatalf("sent proto=%#04x ok=%v, want %#04x", proto, ok, wantProto)
	}
	cf, err := ParseConfigFrame(payload)
	if err != nil {
		t.Fatalf("parse sent frame: %v", err)
	}
	return cf
}

func magicOption(v uint32) Option {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return Option{Type: LCPOptMagicNumber, Data: b}
}

// TestNegotiateLCP_PeerRequestAfterAck reproduces the FortiGate ordering
// seen in a decrypted capture: the gateway's Ack of our request and its own
// request arrive together, Ack first. LCP is only Opened on the gateway's
// side once we Ack its request, so NegotiateLCP must not return before
// doing so.
func TestNegotiateLCP_PeerRequestAfterAck(t *testing.T) {
	link := newFakeLink()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errc := make(chan error, 1)
	go func() { errc <- NegotiateLCP(ctx, link, LCPOptions{MRU: 1354}) }()

	ours := parseSent(t, link.sent(t), ProtoLCP)
	link.deliver(BuildFrame(ProtoLCP, ConfigFrame{Code: CodeConfigureAck, ID: ours.ID, Options: ours.Options}.Marshal()))
	link.deliver(BuildFrame(ProtoLCP, ConfigFrame{Code: CodeConfigureRequest, ID: 1, Options: []Option{magicOption(0x0c02ddbe)}}.Marshal()))

	ack := parseSent(t, link.sent(t), ProtoLCP)
	if ack.Code != CodeConfigureAck || ack.ID != 1 {
		t.Fatalf("got code=%d id=%d, want Ack(id=1) of the gateway's request", ack.Code, ack.ID)
	}
	if err := <-errc; err != nil {
		t.Fatalf("NegotiateLCP: %v", err)
	}
}

// TestNegotiateLCP_NoRetransmitAfterAck: once the peer Acked our request it
// must never be resent while we wait for the peer's own request — a second
// Configure-Request restarts the gateway's already-Opened LCP (observed in
// the capture: the gateway then sent a fresh request id=2 and dropped IPCP).
func TestNegotiateLCP_NoRetransmitAfterAck(t *testing.T) {
	link := newFakeLink()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errc := make(chan error, 1)
	go func() { errc <- NegotiateLCP(ctx, link, LCPOptions{MRU: 1354}) }()

	ours := parseSent(t, link.sent(t), ProtoLCP)
	link.deliver(BuildFrame(ProtoLCP, ConfigFrame{Code: CodeConfigureAck, ID: ours.ID, Options: ours.Options}.Marshal()))
	// The gateway never sends its own request; negotiation ends after the
	// grace period without sending anything else.
	if err := <-errc; err != nil {
		t.Fatalf("NegotiateLCP: %v", err)
	}
	select {
	case pkt := <-link.toPeer:
		t.Fatalf("sent %s after the peer's Ack, want nothing", Describe(pkt))
	default:
	}
}

// TestNegotiateIPCP_FortiGateFlow follows the gateway's real IPCP sequence:
// its own request (with its address) first, then a Nak assigning ours, then
// the Ack. Both directions must be Acked and the assigned address adopted.
func TestNegotiateIPCP_FortiGateFlow(t *testing.T) {
	link := newFakeLink()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type res struct {
		r   IPCPResult
		err error
	}
	resc := make(chan res, 1)
	go func() {
		r, err := NegotiateIPCP(ctx, link, IPCPOptions{})
		resc <- res{r, err}
	}()

	req1 := parseSent(t, link.sent(t), ProtoIPCP)

	gwIP := net.IPv4(198, 51, 100, 130).To4()
	link.deliver(BuildFrame(ProtoIPCP, ConfigFrame{Code: CodeConfigureRequest, ID: 1, Options: []Option{{Type: IPCPOptIPAddress, Data: gwIP}}}.Marshal()))
	if ack := parseSent(t, link.sent(t), ProtoIPCP); ack.Code != CodeConfigureAck || ack.ID != 1 {
		t.Fatalf("got code=%d id=%d, want Ack(id=1) of the gateway's request", ack.Code, ack.ID)
	}

	assigned := net.IPv4(10, 1, 202, 201).To4()
	link.deliver(BuildFrame(ProtoIPCP, ConfigFrame{Code: CodeConfigureNak, ID: req1.ID, Options: []Option{{Type: IPCPOptIPAddress, Data: assigned}}}.Marshal()))
	req2 := parseSent(t, link.sent(t), ProtoIPCP)
	if opt, ok := req2.FindOption(IPCPOptIPAddress); !ok || !bytes.Equal(opt.Data, assigned) {
		t.Fatalf("retried request = %+v, want IP-Address %s", req2, net.IP(assigned))
	}
	link.deliver(BuildFrame(ProtoIPCP, ConfigFrame{Code: CodeConfigureAck, ID: req2.ID, Options: req2.Options}.Marshal()))

	got := <-resc
	if got.err != nil {
		t.Fatalf("NegotiateIPCP: %v", got.err)
	}
	if !got.r.LocalIP.Equal(assigned) || !got.r.PeerIP.Equal(gwIP) {
		t.Fatalf("result = %+v, want local %s peer %s", got.r, net.IP(assigned), net.IP(gwIP))
	}
}

func TestServeLCP_EchoAndLateRequestThenTerminate(t *testing.T) {
	link := newFakeLink()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errc := make(chan error, 1)
	go func() { errc <- ServeLCP(ctx, link) }()

	link.deliver(BuildFrame(ProtoLCP, EchoFrame{Code: CodeEchoRequest, ID: 4, Magic: 0x01020304}.Marshal()))
	_, payload, _ := Protocol(link.sent(t))
	if ef, ok := ParseEchoFrame(payload); !ok || ef.Code != CodeEchoReply || ef.ID != 4 {
		t.Fatalf("got %+v, want Echo-Reply id=4", ef)
	}

	link.deliver(BuildFrame(ProtoLCP, ConfigFrame{Code: CodeConfigureRequest, ID: 2, Options: []Option{magicOption(0xbb27f1bb)}}.Marshal()))
	if ack := parseSent(t, link.sent(t), ProtoLCP); ack.Code != CodeConfigureAck || ack.ID != 2 {
		t.Fatalf("got code=%d id=%d, want Ack(id=2)", ack.Code, ack.ID)
	}

	link.deliver(BuildFrame(ProtoLCP, SimpleFrame{Code: CodeTerminateRequest, ID: 9}.Marshal()))
	_, payload, _ = Protocol(link.sent(t))
	if sf, ok := ParseSimpleFrame(payload); !ok || sf.Code != CodeTerminateAck || sf.ID != 9 {
		t.Fatalf("got %+v, want Terminate-Ack id=9", sf)
	}
	if err := <-errc; !errors.Is(err, ErrPeerTerminated) {
		t.Fatalf("ServeLCP = %v, want ErrPeerTerminated", err)
	}
}

func TestDemux_OtherReceivesData(t *testing.T) {
	link := newFakeLink()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := NewDemux(ctx, link)

	ipv4 := BuildFrame(ProtoIPv4, []byte{0x45, 0, 0, 20})
	ccp := BuildFrame(0x80fd, ConfigFrame{Code: CodeConfigureRequest, ID: 1}.Marshal())
	lcp := BuildFrame(ProtoLCP, EchoFrame{Code: CodeEchoRequest, ID: 1}.Marshal())
	for _, pkt := range [][]byte{ipv4, lcp, ccp} {
		link.deliver(pkt)
	}

	for _, want := range [][]byte{ipv4, ccp} {
		got, err := d.Other().Recv(ctx)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("Other().Recv = %x, %v; want %x", got, err, want)
		}
	}
	if got, err := d.Link(ProtoLCP).Recv(ctx); err != nil || !bytes.Equal(got, lcp) {
		t.Fatalf("LCP Recv = %x, %v; want %x", got, err, lcp)
	}
}

func TestProtocolReject(t *testing.T) {
	info := []byte{1, 1, 0, 4}
	pkt := ProtocolReject(3, 0x80fd, info, 1354)
	want := []byte{0xff, 0x03, 0xc0, 0x21, CodeProtocolReject, 3, 0, 10, 0x80, 0xfd, 1, 1, 0, 4}
	if !bytes.Equal(pkt, want) {
		t.Fatalf("ProtocolReject = % x, want % x", pkt, want)
	}
	if long := ProtocolReject(1, 0x80fd, make([]byte, 2000), 100); len(long) != 4+100 {
		t.Fatalf("truncated reject is %d bytes, want %d", len(long), 4+100)
	}
}

func TestDescribe(t *testing.T) {
	got := Describe(BuildFrame(ProtoLCP, ConfigFrame{Code: CodeConfigureRequest, ID: 1, Options: []Option{{Type: LCPOptMRU, Data: []byte{0x05, 0x4a}}}}.Marshal()))
	if want := "LCP ConfReq id=1 data=0104054a"; got != want {
		t.Fatalf("Describe = %q, want %q", got, want)
	}
}
