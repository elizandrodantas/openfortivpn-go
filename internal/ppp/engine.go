//go:build windows || darwin

package ppp

// Userspace PPP engine, used where there's no (safe) system pppd: on
// Windows there is none at all, and on macOS the system pppd drives the
// legacy com.apple.nke.ppp kernel extension, which has been observed to
// panic the kernel (bounds-check trap, BRK 0x5519) inside its own data
// path while the tunnel is otherwise idle and healthy.
//
// Design: internal/io.RunLoop (the same relay code used with pppd) treats
// Process.PTY() as an HDLC-framed, full-duplex byte stream — exactly what a
// real pppd PTY provides. Here that stream is one end of an in-memory
// net.Pipe(); the other end is driven by wireLink below, which performs the
// same HDLC encode/decode internal/io/relay.go's ptyReader/ptyWriter do, so
// RunLoop needs no platform-specific changes at all. Above that, this engine
// negotiates LCP/IPCP with the gateway (pppproto), then bridges steady-state
// IPv4 traffic between a platform tunDevice and the link.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/hdlc"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp/pppproto"
)

// tunnelMTU matches the MRU we negotiate in LCP (and pppd's "mru 1354").
const tunnelMTU = 1354

// defaultPeerIP is used as the point-to-point destination when the gateway
// doesn't send its own IP-Address in IPCP, matching pppd's ":169.254.2.1".
var defaultPeerIP = net.IPv4(169, 254, 2, 1)

// tunDevice is a virtual layer-3 interface carrying raw IPv4 packets.
type tunDevice interface {
	Name() string
	// ReadPacket blocks for the next outbound IPv4 packet the OS routed
	// onto the interface. The returned slice is only valid until the next
	// call. It must return promptly once ctx is done or Close is called.
	ReadPacket(ctx context.Context) ([]byte, error)
	// WritePacket injects a raw IPv4 packet as inbound traffic.
	WritePacket(ip []byte) error
	// SetAddress assigns the negotiated point-to-point addresses and MTU.
	SetAddress(local, peer net.IP, mtu int) error
	Close() error
}

// engineProcess drives a tunDevice with the Go PPP engine.
type engineProcess struct {
	dev  tunDevice
	link net.Conn // returned by PTY(); read/written (HDLC-framed) by internal/io.RunLoop

	cancel    context.CancelFunc
	done      chan struct{}
	runErr    error
	closeOnce sync.Once
}

// startEngine launches the negotiation + relay engine on dev in the
// background. LCP/IPCP negotiation continues asynchronously and its result
// is only observable through the tunnel coming up (or Wait/Close reporting
// failure).
func startEngine(dev tunDevice) *engineProcess {
	link, engineSide := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	p := &engineProcess{
		dev:    dev,
		link:   link,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go p.run(ctx, engineSide)
	return p
}

// PTY returns the local PPP transport used by the I/O relay goroutines.
func (p *engineProcess) PTY() io.ReadWriter { return p.link }

// run negotiates LCP/IPCP, configures the device's IP address, then relays
// steady-state IPv4 traffic until ctx is cancelled or a fatal error occurs.
func (p *engineProcess) run(ctx context.Context, engineSide net.Conn) {
	defer close(p.done)
	defer engineSide.Close()
	defer func() {
		// This engine's caller (tunnel.go) may not surface Wait()'s error
		// distinctly from the generic relay-loop error its own shutdown
		// produces (closing engineSide causes RunLoop to fail too), so log
		// it here directly — this must never fail silently. A cancelled
		// context is normal shutdown (Ctrl+C / Process.Close), not a failure.
		if p.runErr != nil && !errors.Is(p.runErr, context.Canceled) {
			slog.Error("ppp engine failed", "err", p.runErr)
		}
	}()

	link := newWireLink(engineSide)
	defer link.close()

	// LCP and IPCP negotiate concurrently, not sequentially: comparing a
	// packet capture of a real, working client against ours showed LCP and
	// IPCP Configure-Requests going out together from the start. Some
	// gateways don't necessarily finish LCP before they'll process IPCP —
	// negotiating strictly in sequence can mean waiting on a peer that
	// already sent its (unanswered) IPCP reply. Demux routes each protocol's
	// packets to its own negotiation so they don't race for the same Recv.
	demux := pppproto.NewDemux(ctx, link)
	slog.Debug("ppp engine: negotiating LCP and IPCP concurrently", "iface", p.dev.Name())

	var lcpErr, ipcpErr error
	var result pppproto.IPCPResult
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		lcpErr = pppproto.NegotiateLCP(ctx, demux.Link(pppproto.ProtoLCP), pppproto.LCPOptions{MRU: tunnelMTU})
	}()
	go func() {
		defer wg.Done()
		// Don't request DNS via IPCP: tunnel.go's onIPCPComplete already
		// prefers the DNS servers parsed from the gateway's XML config over
		// anything IPCP negotiates, and it's one less thing that could make
		// our Configure-Request look unlike the minimal one some gateways
		// expect (some may not answer at all if they get options they don't
		// recognize unsolicited, rather than rejecting them).
		result, ipcpErr = pppproto.NegotiateIPCP(ctx, demux.Link(pppproto.ProtoIPCP), pppproto.IPCPOptions{})
	}()
	wg.Wait()

	if lcpErr != nil {
		p.runErr = fmt.Errorf("ppp: LCP negotiation: %w", lcpErr)
		return
	}
	if ipcpErr != nil {
		p.runErr = fmt.Errorf("ppp: IPCP negotiation: %w", ipcpErr)
		return
	}
	slog.Info("ppp engine: LCP+IPCP negotiated", "local", result.LocalIP, "peer", result.PeerIP, "dns1", result.DNS1, "dns2", result.DNS2)

	if result.LocalIP == nil {
		p.runErr = fmt.Errorf("ppp: no local IP negotiated")
		return
	}
	peer := result.PeerIP
	if peer == nil || peer.IsUnspecified() {
		peer = defaultPeerIP
	}
	if err := p.dev.SetAddress(result.LocalIP, peer, tunnelMTU); err != nil {
		p.runErr = fmt.Errorf("ppp: configure %s address: %w", p.dev.Name(), err)
		return
	}

	p.runErr = p.relaySteadyState(ctx, link)
}

// relaySteadyState runs for the life of the connection: it answers LCP
// Echo-Requests and Terminate-Request, forwards decoded IPv4 frames from the
// link into the device, and forwards packets read from the device (real
// outbound traffic routed onto the tunnel) back out over the link.
func (p *engineProcess) relaySteadyState(ctx context.Context, link *wireLink) error {
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
// IPv4 data frames into the device.
func (p *engineProcess) pumpLinkToTun(ctx context.Context, link *wireLink) error {
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
			if err := p.dev.WritePacket(payload); err != nil {
				slog.Warn("ppp engine: failed to inject packet into tunnel device", "iface", p.dev.Name(), "err", err)
			}
		case pppproto.ProtoLCP:
			if err := handleLCPControl(link, payload); errors.Is(err, errPeerTerminated) {
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
func handleLCPControl(link *wireLink, payload []byte) error {
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

// pumpTunToLink reads packets the OS wants to send out through the tunnel
// (real traffic routed onto this interface) and forwards them to the
// gateway over the link.
func (p *engineProcess) pumpTunToLink(ctx context.Context, link *wireLink) error {
	for {
		packet, err := p.dev.ReadPacket(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("%s read packet: %w", p.dev.Name(), err)
		}
		if err := link.Send(pppproto.BuildFrame(pppproto.ProtoIPv4, packet)); err != nil {
			return err
		}
	}
}

// Wait waits for the negotiation/relay engine to finish.
func (p *engineProcess) Wait(ctx context.Context) error {
	select {
	case <-p.done:
		return p.runErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close tears down the engine and the tunnel device. Safe to call multiple
// times.
func (p *engineProcess) Close() {
	p.closeOnce.Do(func() {
		p.cancel()
		p.link.Close() //nolint:errcheck
		if err := p.dev.Close(); err != nil {
			slog.Debug("ppp engine: close tunnel device", "iface", p.dev.Name(), "err", err)
		}
	})
}

// wireLink implements pppproto.Link over engineSide, HDLC-framing/deframing
// exactly as internal/io/relay.go's ptyReader/ptyWriter do, so the byte
// stream RunLoop sees on the other end of the pipe matches what a real pppd
// PTY would produce.
type wireLink struct {
	conn net.Conn

	// sendMu serializes Send: hdlc.Encoder is stateful (its leading-flag
	// tracking) and explicitly not safe for concurrent use, and LCP and
	// IPCP negotiate concurrently (see Demux), both calling Send on this
	// same wireLink from separate goroutines.
	sendMu sync.Mutex
	enc    *hdlc.Encoder // shared across the session — see hdlc.NewEncoder doc

	in      chan []byte
	readMu  sync.Mutex
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
				slog.Debug("ppp engine: hdlc decode error", "err", derr)
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

// writeTimeout bounds every write to the link. Without it, a Write on a
// net.Pipe() blocks until the other end reads — normally near-instant once
// RunLoop's ptyReader is running, but with nothing else bounding it, any
// delay in RunLoop starting (or a stall in it) would block here forever,
// silently bypassing NegotiateLCP/NegotiateIPCP's own timeout entirely,
// since that timeout is only checked once this call returns.
const writeTimeout = pppproto.NegotiateTimeout

// Send HDLC-encodes a raw PPP packet (see pppproto.BuildFrame) and writes it
// to the link. hdlc.Encoder always prepends its own address+control prefix,
// so any FF 03 already in pkt is stripped first to avoid double-framing.
func (w *wireLink) Send(pkt []byte) error {
	w.sendMu.Lock()
	defer w.sendMu.Unlock()

	payload := pppproto.StripPrefix(pkt)
	frame, err := w.enc.Encode(nil, payload)
	if err != nil {
		return err
	}
	if err := w.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
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
