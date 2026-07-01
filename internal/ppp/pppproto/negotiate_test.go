package pppproto

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// fakeLink is an in-memory Link used to test negotiation against a scripted
// peer, without any real transport.
type fakeLink struct {
	toPeer   chan []byte
	fromPeer chan []byte
}

func newFakeLink() *fakeLink {
	return &fakeLink{
		toPeer:   make(chan []byte, 16),
		fromPeer: make(chan []byte, 16),
	}
}

func (l *fakeLink) Send(pkt []byte) error {
	cp := append([]byte(nil), pkt...)
	select {
	case l.toPeer <- cp:
		return nil
	default:
		return context.DeadlineExceeded
	}
}

func (l *fakeLink) Recv(ctx context.Context) ([]byte, error) {
	select {
	case pkt := <-l.fromPeer:
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *fakeLink) deliver(pkt []byte) {
	l.fromPeer <- pkt
}

func (l *fakeLink) sent(t *testing.T) []byte {
	t.Helper()
	select {
	case pkt := <-l.toPeer:
		return pkt
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for outgoing packet")
		return nil
	}
}

func TestNegotiateLCP_SimplePeer(t *testing.T) {
	link := newFakeLink()

	// Drive a scripted peer in the background: it sends its own
	// Configure-Request with just a Magic-Number (which we must Ack) BEFORE
	// acking ours, matching how a real Configure-Ack from the peer arrives
	// once negotiation is already satisfied on our side.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ourReq := link.sent(t)
		proto, payload, ok := Protocol(ourReq)
		if !ok || proto != ProtoLCP {
			t.Errorf("expected LCP request, got proto=%x ok=%v", proto, ok)
			return
		}
		cf, err := ParseConfigFrame(payload)
		if err != nil {
			t.Errorf("parse our request: %v", err)
			return
		}
		if _, ok := cf.FindOption(LCPOptMRU); !ok {
			t.Errorf("expected MRU option in our request")
		}

		// Peer sends its own request with a Magic-Number.
		magic := make([]byte, 4)
		binary.BigEndian.PutUint32(magic, 0xdeadbeef)
		peerReq := ConfigFrame{Code: CodeConfigureRequest, ID: 7, Options: []Option{{Type: LCPOptMagicNumber, Data: magic}}}
		link.deliver(BuildFrame(ProtoLCP, peerReq.Marshal()))

		// Expect our Ack of the peer's request.
		resp := link.sent(t)
		_, payload, _ = Protocol(resp)
		rcf, err := ParseConfigFrame(payload)
		if err != nil {
			t.Errorf("parse our response: %v", err)
			return
		}
		if rcf.Code != CodeConfigureAck || rcf.ID != 7 {
			t.Errorf("expected Ack(id=7) of peer request, got code=%d id=%d", rcf.Code, rcf.ID)
		}

		// Now ack our own request — negotiation should complete right after.
		ack := ConfigFrame{Code: CodeConfigureAck, ID: cf.ID, Options: cf.Options}
		link.deliver(BuildFrame(ProtoLCP, ack.Marshal()))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := NegotiateLCP(ctx, link, LCPOptions{MRU: 1354}); err != nil {
		t.Fatalf("NegotiateLCP failed: %v", err)
	}
	<-done
}

// TestNegotiateLCP_PeerNeverSendsOwnRequest is a regression test for a real
// hang observed against a FortiGate gateway: some gateways only ever
// passively Ack the client's Configure-Request and never propose their own.
// A strict "both sides must negotiate" implementation waits for a peer
// Configure-Request that never arrives and hangs until NegotiateTimeout;
// negotiation must instead complete as soon as the peer Acks our request.
func TestNegotiateLCP_PeerNeverSendsOwnRequest(t *testing.T) {
	link := newFakeLink()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ourReq := link.sent(t)
		_, payload, _ := Protocol(ourReq)
		cf, _ := ParseConfigFrame(payload)
		ack := ConfigFrame{Code: CodeConfigureAck, ID: cf.ID, Options: cf.Options}
		link.deliver(BuildFrame(ProtoLCP, ack.Marshal()))
		// The peer never sends its own Configure-Request — that's the point.
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	if err := NegotiateLCP(ctx, link, LCPOptions{MRU: 1354}); err != nil {
		t.Fatalf("NegotiateLCP failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("NegotiateLCP took %s — should return as soon as our request is Acked, not wait for a peer request that never comes", elapsed)
	}
	<-done
}

func TestNegotiateLCP_RejectsAuthAndCompression(t *testing.T) {
	link := newFakeLink()

	done := make(chan struct{})
	go func() {
		defer close(done)
		ourReq := link.sent(t)
		_, payload, _ := Protocol(ourReq)
		cf, _ := ParseConfigFrame(payload)

		// Peer proposes PFC + ACFC + an auth protocol — all must be rejected.
		peerReq := ConfigFrame{Code: CodeConfigureRequest, ID: 1, Options: []Option{
			{Type: LCPOptProtocolCompress, Data: nil},
			{Type: LCPOptAddrCtrlCompress, Data: nil},
			{Type: LCPOptAuthProtocol, Data: []byte{0xc0, 0x23}},
		}}
		link.deliver(BuildFrame(ProtoLCP, peerReq.Marshal()))

		resp := link.sent(t)
		_, payload, _ = Protocol(resp)
		rcf, _ := ParseConfigFrame(payload)
		if rcf.Code != CodeConfigureReject {
			t.Errorf("expected Configure-Reject, got code=%d", rcf.Code)
			return
		}
		if len(rcf.Options) != 3 {
			t.Errorf("expected all 3 options rejected, got %d", len(rcf.Options))
			return
		}

		// Peer backs off and sends an empty Configure-Request, now acceptable.
		peerReq2 := ConfigFrame{Code: CodeConfigureRequest, ID: 2}
		link.deliver(BuildFrame(ProtoLCP, peerReq2.Marshal()))

		resp2 := link.sent(t)
		_, payload, _ = Protocol(resp2)
		rcf2, _ := ParseConfigFrame(payload)
		if rcf2.Code != CodeConfigureAck || rcf2.ID != 2 {
			t.Errorf("expected Ack(id=2), got code=%d id=%d", rcf2.Code, rcf2.ID)
		}

		// Now ack our own request — negotiation should complete right after.
		ack := ConfigFrame{Code: CodeConfigureAck, ID: cf.ID, Options: cf.Options}
		link.deliver(BuildFrame(ProtoLCP, ack.Marshal()))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := NegotiateLCP(ctx, link, LCPOptions{MRU: 1354}); err != nil {
		t.Fatalf("NegotiateLCP failed: %v", err)
	}
	<-done
}

func TestNegotiateLCP_Timeout(t *testing.T) {
	link := newFakeLink()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := NegotiateLCP(ctx, link, LCPOptions{MRU: 1354}); err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

// TestNegotiateIPCP_NakThenAck mirrors the real exchange observed against a
// FortiGate gateway: we propose 0.0.0.0, the gateway Naks with the assigned
// address and DNS servers, we resend with those values, and get Acked.
func TestNegotiateIPCP_NakThenAck(t *testing.T) {
	link := newFakeLink()
	assigned := net.ParseIP("198.51.100.42").To4()
	dns1 := net.ParseIP("203.0.113.10").To4()
	dns2 := net.ParseIP("203.0.113.11").To4()

	done := make(chan struct{})
	go func() {
		defer close(done)

		// First request: all zeros.
		req1 := link.sent(t)
		_, payload, _ := Protocol(req1)
		cf1, _ := ParseConfigFrame(payload)
		ip, _ := cf1.FindOption(IPCPOptIPAddress)
		if !net.IP(ip.Data).Equal(net.IPv4zero) {
			t.Errorf("expected initial IP-Address proposal 0.0.0.0, got %v", net.IP(ip.Data))
		}

		nak := ConfigFrame{Code: CodeConfigureNak, ID: cf1.ID, Options: []Option{
			{Type: IPCPOptIPAddress, Data: assigned},
			{Type: IPCPOptPrimaryDNS, Data: dns1},
			{Type: IPCPOptSecondaryDNS, Data: dns2},
		}}
		link.deliver(BuildFrame(ProtoIPCP, nak.Marshal()))

		// Second request should carry the Nak'd values.
		req2 := link.sent(t)
		_, payload, _ = Protocol(req2)
		cf2, _ := ParseConfigFrame(payload)
		ip2, _ := cf2.FindOption(IPCPOptIPAddress)
		if !net.IP(ip2.Data).Equal(net.IP(assigned)) {
			t.Errorf("expected resent IP-Address %v, got %v", net.IP(assigned), net.IP(ip2.Data))
		}

		// Peer's own Configure-Request for its side of the link, sent before
		// it Acks ours.
		peerReq := ConfigFrame{Code: CodeConfigureRequest, ID: 1, Options: []Option{
			{Type: IPCPOptIPAddress, Data: net.ParseIP("198.51.100.1").To4()},
		}}
		link.deliver(BuildFrame(ProtoIPCP, peerReq.Marshal()))

		resp := link.sent(t)
		_, payload, _ = Protocol(resp)
		rcf, _ := ParseConfigFrame(payload)
		if rcf.Code != CodeConfigureAck {
			t.Errorf("expected Ack of peer's IPCP request, got code=%d", rcf.Code)
		}

		ack := ConfigFrame{Code: CodeConfigureAck, ID: cf2.ID, Options: cf2.Options}
		link.deliver(BuildFrame(ProtoIPCP, ack.Marshal()))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := NegotiateIPCP(ctx, link, IPCPOptions{RequestDNS: true})
	if err != nil {
		t.Fatalf("NegotiateIPCP failed: %v", err)
	}
	<-done

	if !result.LocalIP.Equal(net.IP(assigned)) {
		t.Errorf("LocalIP = %v, want %v", result.LocalIP, net.IP(assigned))
	}
	if !result.DNS1.Equal(net.IP(dns1)) {
		t.Errorf("DNS1 = %v, want %v", result.DNS1, net.IP(dns1))
	}
	if !result.DNS2.Equal(net.IP(dns2)) {
		t.Errorf("DNS2 = %v, want %v", result.DNS2, net.IP(dns2))
	}
	if !result.PeerIP.Equal(net.ParseIP("198.51.100.1")) {
		t.Errorf("PeerIP = %v, want 198.51.100.1", result.PeerIP)
	}
}

// TestNegotiateIPCP_PeerNeverSendsOwnRequest is the IPCP counterpart to
// TestNegotiateLCP_PeerNeverSendsOwnRequest: negotiation must complete once
// the peer Naks-then-Acks our own request, even if it never proposes its own.
func TestNegotiateIPCP_PeerNeverSendsOwnRequest(t *testing.T) {
	link := newFakeLink()
	assigned := net.ParseIP("198.51.100.42").To4()

	done := make(chan struct{})
	go func() {
		defer close(done)
		req1 := link.sent(t)
		_, payload, _ := Protocol(req1)
		cf1, _ := ParseConfigFrame(payload)
		nak := ConfigFrame{Code: CodeConfigureNak, ID: cf1.ID, Options: []Option{
			{Type: IPCPOptIPAddress, Data: assigned},
		}}
		link.deliver(BuildFrame(ProtoIPCP, nak.Marshal()))

		req2 := link.sent(t)
		_, payload, _ = Protocol(req2)
		cf2, _ := ParseConfigFrame(payload)
		ack := ConfigFrame{Code: CodeConfigureAck, ID: cf2.ID, Options: cf2.Options}
		link.deliver(BuildFrame(ProtoIPCP, ack.Marshal()))
		// The peer never sends its own Configure-Request — that's the point.
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	start := time.Now()
	result, err := NegotiateIPCP(ctx, link, IPCPOptions{})
	if err != nil {
		t.Fatalf("NegotiateIPCP failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("NegotiateIPCP took %s — should return once our request is Acked, not wait for a peer request that never comes", elapsed)
	}
	if !result.LocalIP.Equal(net.IP(assigned)) {
		t.Errorf("LocalIP = %v, want %v", result.LocalIP, net.IP(assigned))
	}
	<-done
}

func TestNegotiateIPCP_RejectsCompression(t *testing.T) {
	link := newFakeLink()

	assigned := net.ParseIP("198.51.100.42").To4()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// A real gateway won't Ack an all-zeros IP-Address; Nak it with the
		// assigned address first, matching TestNegotiateIPCP_NakThenAck.
		req1 := link.sent(t)
		_, payload, _ := Protocol(req1)
		cf1, _ := ParseConfigFrame(payload)
		nak := ConfigFrame{Code: CodeConfigureNak, ID: cf1.ID, Options: []Option{
			{Type: IPCPOptIPAddress, Data: assigned},
		}}
		link.deliver(BuildFrame(ProtoIPCP, nak.Marshal()))

		req2 := link.sent(t)
		_, payload, _ = Protocol(req2)
		cf2, _ := ParseConfigFrame(payload)

		peerReq := ConfigFrame{Code: CodeConfigureRequest, ID: 1, Options: []Option{
			{Type: IPCPOptIPCompression, Data: []byte{0x00, 0x2d, 0x0f, 0x01}},
		}}
		link.deliver(BuildFrame(ProtoIPCP, peerReq.Marshal()))

		resp := link.sent(t)
		_, payload, _ = Protocol(resp)
		rcf, _ := ParseConfigFrame(payload)
		if rcf.Code != CodeConfigureReject {
			t.Errorf("expected Configure-Reject for IP-Compression-Protocol, got code=%d", rcf.Code)
			return
		}

		peerReq2 := ConfigFrame{Code: CodeConfigureRequest, ID: 2}
		link.deliver(BuildFrame(ProtoIPCP, peerReq2.Marshal()))
		resp2 := link.sent(t)
		_, payload, _ = Protocol(resp2)
		rcf2, _ := ParseConfigFrame(payload)
		if rcf2.Code != CodeConfigureAck {
			t.Errorf("expected final Ack, got code=%d", rcf2.Code)
		}

		// Now ack our own request — negotiation should complete right after.
		ack := ConfigFrame{Code: CodeConfigureAck, ID: cf2.ID, Options: cf2.Options}
		link.deliver(BuildFrame(ProtoIPCP, ack.Marshal()))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := NegotiateIPCP(ctx, link, IPCPOptions{}); err != nil {
		t.Fatalf("NegotiateIPCP failed: %v", err)
	}
	<-done
}

func TestFrameMarshalRoundTrip(t *testing.T) {
	cf := ConfigFrame{Code: CodeConfigureRequest, ID: 42, Options: []Option{
		{Type: LCPOptMRU, Data: []byte{0x05, 0x4a}},
		{Type: LCPOptMagicNumber, Data: []byte{1, 2, 3, 4}},
	}}
	raw := cf.Marshal()
	got, err := ParseConfigFrame(raw)
	if err != nil {
		t.Fatalf("ParseConfigFrame: %v", err)
	}
	if got.Code != cf.Code || got.ID != cf.ID || len(got.Options) != len(cf.Options) {
		t.Fatalf("round trip mismatch: got %+v, want %+v", got, cf)
	}
}

func TestBuildFrameAndProtocol(t *testing.T) {
	pkt := BuildFrame(ProtoIPv4, []byte{1, 2, 3})
	if pkt[0] != 0xFF || pkt[1] != 0x03 {
		t.Fatalf("expected FF 03 prefix, got % x", pkt[:2])
	}
	proto, rest, ok := Protocol(pkt)
	if !ok || proto != ProtoIPv4 {
		t.Fatalf("Protocol() = %x, %v, want %x, true", proto, ok, ProtoIPv4)
	}
	if len(rest) != 3 || rest[0] != 1 {
		t.Fatalf("unexpected rest: % x", rest)
	}

	// Without the FF 03 prefix, still parses.
	pkt2 := pkt[2:]
	proto2, _, ok2 := Protocol(pkt2)
	if !ok2 || proto2 != ProtoIPv4 {
		t.Fatalf("Protocol() without prefix = %x, %v", proto2, ok2)
	}
}
