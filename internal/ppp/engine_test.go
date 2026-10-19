//go:build windows || darwin

package ppp

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/hdlc"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp/pppproto"
)

// fakeTun is an in-memory tunDevice.
type fakeTun struct {
	out      chan []byte // packets the "OS" routes onto the tunnel
	in       chan []byte // packets injected by the engine
	mu       sync.Mutex
	local    net.IP
	peer     net.IP
	closed   chan struct{}
	closeOne sync.Once
}

func newFakeTun() *fakeTun {
	return &fakeTun{out: make(chan []byte, 8), in: make(chan []byte, 8), closed: make(chan struct{})}
}

func (d *fakeTun) Name() string { return "faketun0" }

func (d *fakeTun) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case pkt := <-d.out:
		return pkt, nil
	case <-d.closed:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (d *fakeTun) WritePacket(ip []byte) error {
	d.in <- append([]byte(nil), ip...)
	return nil
}

func (d *fakeTun) SetAddress(local, peer net.IP, _ int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.local, d.peer = local, peer
	return nil
}

func (d *fakeTun) Close() error {
	d.closeOne.Do(func() { close(d.closed) })
	return nil
}

// fakeGateway speaks HDLC-framed PPP on the relay side of the engine's
// pipe, like a FortiGate reached through internal/io.RunLoop.
type fakeGateway struct {
	t    *testing.T
	conn io.ReadWriter
	enc  *hdlc.Encoder
	rx   chan []byte
}

func newFakeGateway(t *testing.T, conn io.ReadWriter) *fakeGateway {
	g := &fakeGateway{t: t, conn: conn, enc: hdlc.NewEncoder(), rx: make(chan []byte, 64)}
	go func() {
		dec := hdlc.Decoder{}
		buf := make([]byte, 65536)
		n := 0
		for {
			m, err := conn.Read(buf[n:])
			if err != nil {
				close(g.rx)
				return
			}
			n += m
			start := 0
			for {
				fs, fl, ferr := dec.FindFrame(buf[:n], &start)
				if ferr != nil {
					break
				}
				pkt, derr := dec.Decode(buf[fs : fs+fl])
				start = fs + fl
				if derr == nil {
					g.rx <- pkt
				}
			}
			if start > 0 && start <= n {
				copy(buf, buf[start:n])
				n -= start
			}
		}
	}()
	return g
}

func (g *fakeGateway) send(pkt []byte) {
	g.t.Helper()
	frame, _ := g.enc.Encode(nil, pppproto.StripPrefix(pkt))
	if _, err := g.conn.Write(frame); err != nil {
		g.t.Fatalf("gateway write: %v", err)
	}
}

// expect returns the next packet of proto the engine sent, skipping others.
func (g *fakeGateway) expect(proto uint16) pppproto.ConfigFrame {
	g.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case pkt, ok := <-g.rx:
			if !ok {
				g.t.Fatal("engine closed the link")
			}
			p, payload, ok := pppproto.Protocol(pkt)
			if !ok || p != proto {
				continue
			}
			cf, err := pppproto.ParseConfigFrame(payload)
			if err != nil {
				g.t.Fatalf("parse %s: %v", pppproto.Describe(pkt), err)
			}
			return cf
		case <-timeout:
			g.t.Fatalf("timed out waiting for proto %#04x", proto)
		}
	}
}

func (g *fakeGateway) expectRaw(proto uint16) []byte {
	g.t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case pkt, ok := <-g.rx:
			if !ok {
				g.t.Fatal("engine closed the link")
			}
			if p, payload, ok := pppproto.Protocol(pkt); ok && p == proto {
				return payload
			}
		case <-timeout:
			g.t.Fatalf("timed out waiting for proto %#04x", proto)
		}
	}
}

// TestEngine_FortiGateSession drives a full session the way the gateway in
// the decrypted capture does, and checks the engine never sends IPCP before
// LCP is Opened, answers both of the gateway's requests, and relays data
// in both directions.
func TestEngine_FortiGateSession(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(testLogWriter{t}, &slog.HandlerOptions{Level: levelFrames})))
	defer slog.SetDefault(prev)

	dev := newFakeTun()
	p := startEngine(dev)
	defer p.Close()
	gw := newFakeGateway(t, p.PTY())

	// LCP: the engine's request comes first and alone — no IPCP yet.
	select {
	case pkt := <-gw.rx:
		if proto, _, _ := pppproto.Protocol(pkt); proto != pppproto.ProtoLCP {
			t.Fatalf("first frame is %s, want an LCP Configure-Request", pppproto.Describe(pkt))
		}
		_, payload, _ := pppproto.Protocol(pkt)
		cf, _ := pppproto.ParseConfigFrame(payload)
		// Gateway: Ack ours, then its own request, in one burst.
		gw.send(pppproto.BuildFrame(pppproto.ProtoLCP, pppproto.ConfigFrame{Code: pppproto.CodeConfigureAck, ID: cf.ID, Options: cf.Options}.Marshal()))
		gw.send(pppproto.BuildFrame(pppproto.ProtoLCP, pppproto.ConfigFrame{Code: pppproto.CodeConfigureRequest, ID: 1,
			Options: []pppproto.Option{{Type: pppproto.LCPOptMagicNumber, Data: []byte{0x0c, 0x02, 0xdd, 0xbe}}}}.Marshal()))
	case <-time.After(5 * time.Second):
		t.Fatal("no LCP request from the engine")
	}
	if ack := gw.expect(pppproto.ProtoLCP); ack.Code != pppproto.CodeConfigureAck || ack.ID != 1 {
		t.Fatalf("got LCP code=%d id=%d, want Ack(id=1)", ack.Code, ack.ID)
	}

	// IPCP: the gateway's own request, then Nak with our address, then Ack.
	gw.send(pppproto.BuildFrame(pppproto.ProtoIPCP, pppproto.ConfigFrame{Code: pppproto.CodeConfigureRequest, ID: 1,
		Options: []pppproto.Option{{Type: pppproto.IPCPOptIPAddress, Data: []byte{198, 51, 100, 130}}}}.Marshal()))
	assigned := []byte{10, 1, 202, 201}
	for acked := false; !acked; {
		cf := gw.expect(pppproto.ProtoIPCP)
		switch cf.Code {
		case pppproto.CodeConfigureAck:
			if cf.ID != 1 {
				t.Fatalf("Ack of unexpected id %d", cf.ID)
			}
		case pppproto.CodeConfigureRequest:
			if opt, _ := cf.FindOption(pppproto.IPCPOptIPAddress); bytes.Equal(opt.Data, assigned) {
				gw.send(pppproto.BuildFrame(pppproto.ProtoIPCP, pppproto.ConfigFrame{Code: pppproto.CodeConfigureAck, ID: cf.ID, Options: cf.Options}.Marshal()))
				acked = true
				continue
			}
			gw.send(pppproto.BuildFrame(pppproto.ProtoIPCP, pppproto.ConfigFrame{Code: pppproto.CodeConfigureNak, ID: cf.ID,
				Options: []pppproto.Option{{Type: pppproto.IPCPOptIPAddress, Data: assigned}}}.Marshal()))
		}
	}

	// Steady state: a keepalive is answered, data flows both ways, and an
	// unsupported protocol is Protocol-Rejected.
	gw.send(pppproto.BuildFrame(pppproto.ProtoLCP, pppproto.EchoFrame{Code: pppproto.CodeEchoRequest, ID: 7, Magic: 1}.Marshal()))
	if payload := gw.expectRaw(pppproto.ProtoLCP); payload[0] != pppproto.CodeEchoReply {
		t.Fatalf("got LCP code %d, want Echo-Reply", payload[0])
	}

	inbound := []byte{0x45, 0, 0, 20, 1, 2, 3, 4}
	deadline := time.After(5 * time.Second)
	gw.send(pppproto.BuildFrame(pppproto.ProtoIPv4, inbound))
	select {
	case got := <-dev.in:
		if !bytes.Equal(got, inbound) {
			t.Fatalf("injected % x, want % x", got, inbound)
		}
	case <-deadline:
		t.Fatal("inbound IPv4 never reached the device")
	}
	dev.mu.Lock()
	local, peer := dev.local, dev.peer
	dev.mu.Unlock()
	if !local.Equal(net.IP(assigned)) {
		t.Fatalf("device address = %s, want %s", local, net.IP(assigned))
	}
	// The gateway's IPCP address (198.51.100.130 here) is its public one;
	// using it as the point-to-point peer would route the tunnel's own TLS
	// connection into the tunnel.
	if !peer.Equal(tunnelPeerIP) {
		t.Fatalf("device peer = %s, want %s", peer, tunnelPeerIP)
	}

	outbound := []byte{0x45, 0, 0, 20, 5, 6, 7, 8}
	dev.out <- outbound
	if got := gw.expectRaw(pppproto.ProtoIPv4); !bytes.Equal(got, outbound) {
		t.Fatalf("gateway got % x, want % x", got, outbound)
	}

	gw.send(pppproto.BuildFrame(0x80fd, pppproto.ConfigFrame{Code: pppproto.CodeConfigureRequest, ID: 1}.Marshal()))
	if payload := gw.expectRaw(pppproto.ProtoLCP); payload[0] != pppproto.CodeProtocolReject || payload[4] != 0x80 || payload[5] != 0xfd {
		t.Fatalf("got LCP % x, want Protocol-Reject of CCP", payload)
	}

	// Gateway hangs up: the engine Acks and ends.
	gw.send(pppproto.BuildFrame(pppproto.ProtoLCP, pppproto.SimpleFrame{Code: pppproto.CodeTerminateRequest, ID: 3}.Marshal()))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.Wait(ctx); err == nil || ctx.Err() != nil {
		t.Fatalf("Wait = %v, want the session to end with an error", err)
	}
}

// testLogWriter routes slog output (including the engine's frame log) to
// the test log, so a failure shows the exchange that led to it.
type testLogWriter struct{ t *testing.T }

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(string(bytes.TrimRight(p, "\n")))
	return len(p), nil
}
