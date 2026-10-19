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
	"sync/atomic"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/hdlc"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp/pppproto"
)

// tunnelMTU matches the MRU we negotiate in LCP (and pppd's "mru 1354").
const tunnelMTU = 1354

// tunnelPeerIP is always used as the point-to-point destination of the
// tunnel interface, matching pppd's ":169.254.2.1" (see buildArgs in
// pppd_unix.go). The gateway's own IPCP IP-Address can't be used: a
// FortiGate sends its public address — the very one the TLS connection
// carrying the tunnel goes to — so using it installs a host route to the
// gateway through the tunnel, looping the tunnel's own traffic into itself
// until the TLS connection times out.
var tunnelPeerIP = net.IPv4(169, 254, 2, 1)

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

// run negotiates LCP then IPCP, configures the device's IP address, then
// relays steady-state IPv4 traffic until ctx is cancelled or a fatal error
// occurs.
//
// The order mirrors pppd and what a FortiGate expects (confirmed against a
// decrypted capture): IPCP only starts once LCP is Opened in both
// directions, since the gateway discards IPCP before that; and LCP/IPCP
// keep being answered for the whole session (ServeLCP/ServeIPCP), since the
// gateway's own requests and keepalives can arrive after our side finished
// negotiating.
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The first failure of any background goroutine ends the session; it's
	// kept so it can be reported instead of the context.Canceled it causes
	// everywhere else.
	errCh := make(chan error, 1)
	fail := func(err error) {
		select {
		case errCh <- err:
		default:
		}
		cancel()
	}
	firstErr := func(fallback error) error {
		select {
		case err := <-errCh:
			return err
		default:
			return fallback
		}
	}

	link := newWireLink(engineSide)
	defer link.close()

	// The demux is the link's only reader for the whole session.
	demux := pppproto.NewDemux(ctx, link)
	var lcpOpen, tunReady atomic.Bool
	go func() { fail(p.pumpLinkToTun(ctx, link, demux.Other(), &lcpOpen, &tunReady)) }()

	slog.Debug("ppp engine: negotiating LCP", "iface", p.dev.Name())
	lcpLink := demux.Link(pppproto.ProtoLCP)
	if err := pppproto.NegotiateLCP(ctx, lcpLink, pppproto.LCPOptions{MRU: tunnelMTU}); err != nil {
		p.runErr = firstErr(fmt.Errorf("ppp: LCP negotiation: %w", err))
		return
	}
	lcpOpen.Store(true)
	go func() { fail(pppproto.ServeLCP(ctx, lcpLink)) }()

	slog.Debug("ppp engine: LCP opened, negotiating IPCP")
	ipcpLink := demux.Link(pppproto.ProtoIPCP)
	// Don't request DNS via IPCP: tunnel.go's onIPCPComplete already
	// prefers the DNS servers parsed from the gateway's XML config over
	// anything IPCP negotiates, and it's one less thing that could make our
	// Configure-Request look unlike the minimal one some gateways expect.
	result, err := pppproto.NegotiateIPCP(ctx, ipcpLink, pppproto.IPCPOptions{})
	if err != nil {
		p.runErr = firstErr(fmt.Errorf("ppp: IPCP negotiation: %w", err))
		return
	}
	go func() { fail(pppproto.ServeIPCP(ctx, ipcpLink)) }()
	slog.Info("ppp engine: LCP+IPCP negotiated", "local", result.LocalIP, "peer", result.PeerIP, "dns1", result.DNS1, "dns2", result.DNS2)

	if result.LocalIP == nil {
		p.runErr = fmt.Errorf("ppp: no local IP negotiated")
		return
	}
	if err := p.dev.SetAddress(result.LocalIP, tunnelPeerIP, tunnelMTU); err != nil {
		p.runErr = fmt.Errorf("ppp: configure %s address: %w", p.dev.Name(), err)
		return
	}
	tunReady.Store(true)
	go func() { fail(p.pumpTunToLink(ctx, link)) }()

	<-ctx.Done()
	p.runErr = firstErr(ctx.Err())
}

// pumpLinkToTun handles every packet that is neither LCP nor IPCP: IPv4
// data is injected into the device once it's configured (anything earlier
// is dropped), and any other protocol is answered with an LCP
// Protocol-Reject once LCP is Opened (RFC 1661 section 5.7), so the peer
// stops trying to negotiate it (e.g. CCP, IPV6CP).
func (p *engineProcess) pumpLinkToTun(ctx context.Context, link *wireLink, other pppproto.Link, lcpOpen, tunReady *atomic.Bool) error {
	var rejectID byte
	for {
		pkt, err := other.Recv(ctx)
		if err != nil {
			return err
		}
		proto, payload, ok := pppproto.Protocol(pkt)
		if !ok {
			continue
		}
		if proto == pppproto.ProtoIPv4 {
			if !tunReady.Load() {
				continue
			}
			if err := p.dev.WritePacket(payload); err != nil {
				slog.Warn("ppp engine: failed to inject packet into tunnel device", "iface", p.dev.Name(), "err", err)
			}
			continue
		}
		if !lcpOpen.Load() {
			continue
		}
		rejectID++
		if err := link.Send(pppproto.ProtocolReject(rejectID, proto, payload, tunnelMTU)); err != nil {
			return err
		}
	}
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
			// Advance to the frame's closing 0x7E, not past it: that flag
			// also opens the next frame (see hdlc.Decoder.FindFrame).
			start = frameStart + frameLen
			if derr != nil {
				slog.Debug("ppp engine: hdlc decode error", "err", derr)
				continue
			}
			logFrame("rx", pkt)
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

	logFrame("tx", pkt)
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

// levelFrames is the -vv level (DEBUG_DETAILS, see cmd/openfortivpn) at
// which every control frame on the link is logged.
const levelFrames = slog.Level(-8)

// logFrame logs a non-IPv4 PPP packet (LCP, IPCP, anything the gateway
// tries to negotiate), so a stuck negotiation can be diagnosed from the
// log alone instead of a decrypted packet capture.
func logFrame(dir string, pkt []byte) {
	if proto, _, ok := pppproto.Protocol(pkt); ok && proto == pppproto.ProtoIPv4 {
		return
	}
	ctx := context.Background()
	if !slog.Default().Enabled(ctx, levelFrames) {
		return
	}
	slog.Log(ctx, levelFrames, "ppp "+dir, "frame", pppproto.Describe(pkt))
}
