//go:build windows

// Package ppp implements PPP tunnel management. On Windows there is no pppd
// daemon available, so this file drives a wintun virtual TUN adapter and
// negotiates LCP/IPCP itself (internal/ppp/pppproto) instead of shelling out
// to a system PPP daemon like pppd_unix.go does.
//
// Design: internal/io.RunLoop (the same relay code used on Unix) treats
// Process.PTY() as an HDLC-framed, full-duplex byte stream — exactly what a
// real pppd PTY provides. Here that stream is one end of an in-memory
// net.Pipe(); the other end is driven by wireLink below, which performs the
// same HDLC encode/decode internal/io/relay.go's ptyReader/ptyWriter do, so
// RunLoop needs no Windows-specific changes at all. Above that, this engine
// negotiates LCP/IPCP with the gateway (pppproto), then bridges steady-state
// IPv4 traffic between the wintun adapter and the link.
package ppp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/hdlc"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp/pppproto"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp/wintundll"
)

const (
	defaultAdapterName = "openfortivpn"
	ringCapacity        = wintun.RingCapacityMin // 128 KiB; must be a power of two
	waitPollInterval    = 200 * time.Millisecond
)

// Process wraps a wintun TUN adapter and the Go PPP engine that negotiates
// LCP/IPCP with the FortiGate gateway and relays IPv4 traffic to/from the
// adapter. Requires Administrator privileges (driver install/adapter
// creation).
type Process struct {
	adapter *wintun.Adapter
	session wintun.Session
	ifName  string

	link net.Conn // returned by PTY(); read/written (HDLC-framed) by internal/io.RunLoop

	cancel    context.CancelFunc
	done      chan struct{}
	runErr    error
	closeOnce sync.Once
}

// PTY returns the local PPP transport used by the I/O relay goroutines.
func (p *Process) PTY() net.Conn { return p.link }

// Start creates a wintun adapter and launches the negotiation + relay engine
// in the background. It returns as soon as the adapter exists; LCP/IPCP
// negotiation continues asynchronously and its result is only observable
// through the tunnel coming up (or Wait/Close reporting failure).
func Start(cfg *config.Config) (*Process, error) {
	name := defaultAdapterName
	if cfg.PPPDIfname != "" {
		name = cfg.PPPDIfname
	}

	if err := wintundll.Ensure(); err != nil {
		return nil, fmt.Errorf("ppp: prepare wintun.dll: %w", err)
	}

	adapter, err := wintun.CreateAdapter(name, "Wintun", nil)
	if err != nil {
		return nil, fmt.Errorf("ppp: create wintun adapter %q (are you running as Administrator?): %w", name, err)
	}
	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close() //nolint:errcheck
		return nil, fmt.Errorf("ppp: start wintun session: %w", err)
	}

	link, engineSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	p := &Process{
		adapter: adapter,
		session: session,
		ifName:  name,
		link:    link,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	go p.run(ctx, cfg, engineSide)

	return p, nil
}

// run negotiates LCP/IPCP, configures the adapter's IP address, then relays
// steady-state IPv4 traffic until ctx is cancelled or a fatal error occurs.
func (p *Process) run(ctx context.Context, cfg *config.Config, engineSide net.Conn) {
	defer close(p.done)
	defer engineSide.Close()

	link := newWireLink(engineSide)
	defer link.close()

	slog.Debug("windows ppp: negotiating LCP")
	if err := pppproto.NegotiateLCP(ctx, link, pppproto.LCPOptions{MRU: 1354}); err != nil {
		p.runErr = fmt.Errorf("ppp: LCP negotiation: %w", err)
		return
	}

	slog.Debug("windows ppp: negotiating IPCP")
	result, err := pppproto.NegotiateIPCP(ctx, link, pppproto.IPCPOptions{RequestDNS: cfg.PPPDUsePeerDNS || true})
	if err != nil {
		p.runErr = fmt.Errorf("ppp: IPCP negotiation: %w", err)
		return
	}
	slog.Info("windows ppp: IPCP negotiated", "local", result.LocalIP, "peer", result.PeerIP, "dns1", result.DNS1, "dns2", result.DNS2)

	if err := configureAdapterAddress(p.ifName, result.LocalIP); err != nil {
		p.runErr = fmt.Errorf("ppp: configure adapter address: %w", err)
		return
	}

	p.runErr = p.relaySteadyState(ctx, link)
}

// relaySteadyState runs for the life of the connection: it answers LCP
// Echo-Requests and Terminate-Request, forwards decoded IPv4 frames from the
// link into the wintun adapter, and forwards packets read from the adapter
// (real outbound traffic routed onto the tunnel) back out over the link.
func (p *Process) relaySteadyState(ctx context.Context, link *wireLink) error {
	errCh := make(chan error, 2)

	go func() {
		errCh <- p.pumpTunToLink(ctx, link)
	}()
	go func() {
		errCh <- p.pumpLinkToTun(ctx, link)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// pumpLinkToTun reads decoded PPP packets arriving from the gateway (via the
// link), answers control-protocol frames (LCP Echo/Terminate), and injects
// IPv4 data frames into the wintun adapter.
func (p *Process) pumpLinkToTun(ctx context.Context, link *wireLink) error {
	for {
		pkt, err := link.Recv(ctx)
		if err != nil {
			return err
		}
		proto, payload, ok := pppproto.Protocol(pkt)
		if !ok {
			continue
		}
		switch proto {
		case pppproto.ProtoIPv4:
			if err := p.injectIntoTun(payload); err != nil {
				slog.Warn("windows ppp: failed to inject packet into wintun", "err", err)
			}
		case pppproto.ProtoLCP:
			if err := p.handleLCPControl(link, payload); errors.Is(err, errPeerTerminated) {
				return err
			}
		default:
			// Unknown protocol — reject it so the peer knows we don't
			// support it, matching standard PPP behavior.
			if cf, perr := pppproto.ParseConfigFrame(payload); perr == nil {
				reject := pppproto.ConfigFrame{Code: pppproto.CodeProtocolReject, ID: cf.ID}
				_ = link.Send(pppproto.BuildFrame(pppproto.ProtoLCP, reject.Marshal()))
			}
		}
	}
}

var errPeerTerminated = errors.New("ppp: peer sent Terminate-Request")

// handleLCPControl answers Echo-Request/Terminate-Request frames seen during
// steady state (negotiation itself already handles Echo-Request internally).
func (p *Process) handleLCPControl(link *wireLink, payload []byte) error {
	if len(payload) < 1 {
		return nil
	}
	switch payload[0] {
	case pppproto.CodeEchoRequest:
		if ef, ok := pppproto.ParseEchoFrame(payload); ok {
			reply := pppproto.EchoFrame{Code: pppproto.CodeEchoReply, ID: ef.ID, Magic: ef.Magic}
			return link.Send(pppproto.BuildFrame(pppproto.ProtoLCP, reply.Marshal()))
		}
	case pppproto.CodeTerminateRequest:
		if sf, ok := pppproto.ParseSimpleFrame(payload); ok {
			ack := pppproto.SimpleFrame{Code: pppproto.CodeTerminateAck, ID: sf.ID}
			_ = link.Send(pppproto.BuildFrame(pppproto.ProtoLCP, ack.Marshal()))
		}
		return errPeerTerminated
	}
	return nil
}

// injectIntoTun writes a raw IPv4 packet into the wintun adapter so the
// Windows network stack sees it as inbound traffic on the tunnel interface.
func (p *Process) injectIntoTun(ipPacket []byte) error {
	buf, err := p.session.AllocateSendPacket(len(ipPacket))
	if err != nil {
		return err
	}
	copy(buf, ipPacket)
	p.session.SendPacket(buf)
	return nil
}

// pumpTunToLink reads packets Windows wants to send out through the tunnel
// (real traffic routed onto this interface) and forwards them to the
// gateway over the link.
func (p *Process) pumpTunToLink(ctx context.Context, link *wireLink) error {
	waitEvent := p.session.ReadWaitEvent()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		packet, err := p.session.ReceivePacket()
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				// Nothing pending — wait briefly (bounded so ctx
				// cancellation is still observed promptly) then retry.
				_, _ = windows.WaitForSingleObject(waitEvent, uint32(waitPollInterval/time.Millisecond))
				continue
			}
			return fmt.Errorf("wintun receive packet: %w", err)
		}

		frame := pppproto.BuildFrame(pppproto.ProtoIPv4, packet)
		sendErr := link.Send(frame)
		p.session.ReleaseReceivePacket(packet)
		if sendErr != nil {
			return sendErr
		}
	}
}

// Wait waits for the negotiation/relay engine to finish.
func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		return p.runErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the engine, wintun session and adapter. Safe to call
// multiple times.
func (p *Process) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.link.Close() //nolint:errcheck
		p.session.End()
		p.adapter.Close() //nolint:errcheck
	})
}

// configureAdapterAddress assigns the negotiated local IP to the wintun
// adapter as a /32 (matching classic point-to-point PPP semantics — actual
// routing is handled separately by internal/ipv4/route_windows.go).
func configureAdapterAddress(ifName string, localIP net.IP) error {
	if localIP == nil {
		return fmt.Errorf("no local IP negotiated")
	}
	args := []string{"interface", "ip", "set", "address",
		"name=" + ifName, "source=static",
		"addr=" + localIP.String(), "mask=255.255.255.255",
	}
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// wireLink implements pppproto.Link over engineSide, HDLC-framing/deframing
// exactly as internal/io/relay.go's ptyReader/ptyWriter do, so the byte
// stream RunLoop sees on the other end of the pipe matches what a real pppd
// PTY would produce.
type wireLink struct {
	conn net.Conn
	enc  *hdlc.Encoder // shared across the session — see hdlc.NewEncoder doc

	in     chan []byte
	readMu sync.Mutex
	readErr error
	closed  chan struct{}
}

func newWireLink(conn net.Conn) *wireLink {
	w := &wireLink{
		conn:   conn,
		enc:    hdlc.NewEncoder(),
		in:     make(chan []byte, 64),
		closed: make(chan struct{}),
	}
	go w.readLoop()
	return w
}

func (w *wireLink) readLoop() {
	dec := hdlc.Decoder{}
	buf := make([]byte, 65536)
	bufLen := 0
	defer close(w.in)

	for {
		n, err := w.conn.Read(buf[bufLen:])
		if err != nil {
			w.readMu.Lock()
			w.readErr = err
			w.readMu.Unlock()
			return
		}
		bufLen += n

		start := 0
		for {
			frameStart, frameLen, ferr := dec.FindFrame(buf[:bufLen], &start)
			if ferr != nil {
				break
			}
			pkt, derr := dec.Decode(buf[frameStart : frameStart+frameLen])
			start = frameStart + frameLen + 1
			if derr != nil {
				slog.Debug("windows ppp: hdlc decode error", "err", derr)
				continue
			}
			select {
			case w.in <- pkt:
			case <-w.closed:
				return
			}
		}

		if start > 0 && start <= bufLen {
			copy(buf, buf[start:bufLen])
			bufLen -= start
		}
	}
}

// Send HDLC-encodes a raw PPP packet (see pppproto.BuildFrame) and writes it
// to the link. hdlc.Encoder always prepends its own address+control prefix,
// so any FF 03 already in pkt is stripped first to avoid double-framing.
func (w *wireLink) Send(pkt []byte) error {
	payload := pppproto.StripPrefix(pkt)
	frame, err := w.enc.Encode(nil, payload)
	if err != nil {
		return err
	}
	_, err = w.conn.Write(frame)
	return err
}

func (w *wireLink) Recv(ctx context.Context) ([]byte, error) {
	select {
	case pkt, ok := <-w.in:
		if !ok {
			w.readMu.Lock()
			err := w.readErr
			w.readMu.Unlock()
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("ppp: link closed")
		}
		return pkt, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (w *wireLink) close() {
	select {
	case <-w.closed:
	default:
		close(w.closed)
	}
}
