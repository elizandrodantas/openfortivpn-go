package io

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/elizandrodantas/openfortivpn-go/internal/hdlc"
)

// cancelDeadline is a time in the past; assigning it as a deadline immediately
// expires any pending or future I/O on the connection.
var cancelDeadline = time.Unix(0, 1)

// IPCPInfo holds the network configuration extracted from IPCP negotiation.
type IPCPInfo struct {
	AssignedIP net.IP
	NS1        net.IP
	NS2        net.IP
}

// LoopConfig configures the I/O relay goroutines.
type LoopConfig struct {
	TLSConn *tls.Conn
	// PTY is the local PPP transport: a real pppd PTY master on Unix, or an
	// in-memory pipe fed by a Go PPP engine on Windows (see
	// internal/ppp/tun_windows.go). Only Read/Write are used.
	PTY      io.ReadWriter
	OnIPCP   func(IPCPInfo) // called once when IPCP Config-ACK is seen
	OnCancel func()         // optional: called on ctx cancellation to unblock PTY I/O
}

// RunLoop starts 5 goroutines that bidirectionally relay data between the TLS
// socket (gateway) and the pppd PTY:
//
//	sslReader → sslToPTY channel → ptyWriter
//	ptyReader → ptyToSSL channel → sslWriter
//	ifConfigMonitor (watches for IPCP Config-ACK)
//
// It blocks until the context is cancelled or an I/O error occurs on any goroutine.
func RunLoop(ctx context.Context, cfg *LoopConfig) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Bounded channels for backpressure (equivalent to C packet pool size)
	sslToPTY := make(chan []byte, 64)
	ptyToSSL := make(chan []byte, 64)

	// pptdReadyCh is closed by ptyReader after the first successful PTY read,
	// signalling ptyWriter that pppd is ready to receive data.
	// Mirrors the C sem_pppd_ready semaphore.
	pptdReadyCh := make(chan struct{})
	var pptdReadyOnce sync.Once

	// ipcpCh carries the IPCP Config-ACK event from sslReader to ifConfigMonitor.
	ipcpCh := make(chan IPCPInfo, 1)

	errCh := make(chan error, 5)
	var wg sync.WaitGroup

	wg.Add(5)
	go func() { defer wg.Done(); sslReader(ctx, cfg, sslToPTY, ipcpCh, errCh) }()
	go func() { defer wg.Done(); sslWriter(ctx, cfg, ptyToSSL, errCh) }()
	go func() {
		defer wg.Done()
		ptyReader(ctx, cfg, ptyToSSL, &pptdReadyOnce, pptdReadyCh, errCh)
	}()
	go func() { defer wg.Done(); ptyWriter(ctx, cfg, sslToPTY, pptdReadyCh, errCh) }()
	go func() { defer wg.Done(); ifConfigMonitor(ctx, cfg, ipcpCh, errCh) }()

	// When context is cancelled (Ctrl+C / SIGTERM), unblock goroutines stuck in
	// blocking I/O: set an expired TLS deadline (unblocks sslReader/sslWriter)
	// and call OnCancel (kills pppd → PTY EOF → unblocks ptyReader).
	// If an I/O error fires first, close stoppedCh to let the watcher exit.
	stoppedCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = cfg.TLSConn.SetDeadline(cancelDeadline)
			if cfg.OnCancel != nil {
				cfg.OnCancel()
			}
		case <-stoppedCh:
		}
	}()

	select {
	case err := <-errCh:
		close(stoppedCh)
		cancel()
		wg.Wait()
		if err != nil {
			return fmt.Errorf("io: relay: %w", err)
		}
		return nil
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	}
}

// sslReader reads PPP packets from the TLS socket and forwards them to sslToPTY.
// It also inspects IPCP packets and sends IPCP events to ipcpCh.
func sslReader(ctx context.Context, cfg *LoopConfig, out chan<- []byte, ipcpCh chan<- IPCPInfo, errCh chan<- error) {
	var ipcpSent bool
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		pkt, err := ReadPacket(cfg.TLSConn)
		if err != nil {
			select {
			case <-ctx.Done():
				return // context cancelled — error is from forced deadline, not a fault
			default:
				select {
				case errCh <- fmt.Errorf("sslReader: %w", err):
				default:
				}
				return
			}
		}

		if !ipcpSent {
			if info, ok := extractIPCP(pkt); ok {
				ipcpSent = true
				select {
				case ipcpCh <- info:
				default:
				}
			}
		}

		select {
		case out <- pkt:
		case <-ctx.Done():
			return
		}
	}
}

// sslWriter reads encoded PPP packets from ptyToSSL and writes them to TLS.
func sslWriter(ctx context.Context, cfg *LoopConfig, in <-chan []byte, errCh chan<- error) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-in:
			if !ok {
				return
			}
			if err := WritePacket(cfg.TLSConn, pkt); err != nil {
				select {
				case errCh <- fmt.Errorf("sslWriter: %w", err):
				default:
				}
				return
			}
		}
	}
}

// ptyReader reads from the pppd PTY, decodes HDLC frames, and forwards PPP
// packets to ptyToSSL. It closes pptdReadyCh on first successful read.
func ptyReader(ctx context.Context, cfg *LoopConfig, out chan<- []byte, once *sync.Once, readyCh chan<- struct{}, errCh chan<- error) {
	dec := hdlc.Decoder{}
	buf := make([]byte, 65536)
	bufLen := 0

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := cfg.PTY.Read(buf[bufLen:])
		if err != nil {
			select {
			case <-ctx.Done():
				return // context cancelled — PTY closed during shutdown
			default:
				select {
				case errCh <- fmt.Errorf("ptyReader: %w", err):
				default:
				}
				return
			}
		}
		bufLen += n

		// Signal pppd is ready after first read
		once.Do(func() { close(readyCh) })

		start := 0
		for {
			frameStart, frameLen, ferr := dec.FindFrame(buf[:bufLen], &start)
			if ferr != nil {
				break
			}
			pkt, derr := dec.Decode(buf[frameStart : frameStart+frameLen])
			if derr != nil {
				slog.Debug("hdlc decode error", "err", derr)
				start = frameStart + frameLen + 1
				continue
			}

			// Advance past the consumed frame (including trailing 0x7E)
			start = frameStart + frameLen + 1

			select {
			case out <- pkt:
			case <-ctx.Done():
				return
			}
		}

		// Compact buffer: keep unconsumed bytes
		if start > 0 && start <= bufLen {
			copy(buf, buf[start:bufLen])
			bufLen -= start
		}
	}
}

// ptyWriter waits for pptdReadyCh (pppd is ready), then HDLC-encodes packets
// from sslToPTY and writes them to the PTY.
func ptyWriter(ctx context.Context, cfg *LoopConfig, in <-chan []byte, readyCh <-chan struct{}, errCh chan<- error) {
	// Wait for pppd to signal readiness (first byte from ptyReader)
	select {
	case <-readyCh:
	case <-ctx.Done():
		return
	}

	enc := hdlc.NewEncoder()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-in:
			if !ok {
				return
			}
			frame, err := enc.Encode(nil, pkt)
			if err != nil {
				select {
				case errCh <- fmt.Errorf("ptyWriter encode: %w", err):
				default:
				}
				return
			}
			if _, err := cfg.PTY.Write(frame); err != nil {
				select {
				case errCh <- fmt.Errorf("ptyWriter write: %w", err):
				default:
				}
				return
			}
		}
	}
}

// ifConfigMonitor waits for the IPCP Config-ACK event and then calls OnIPCP.
func ifConfigMonitor(ctx context.Context, cfg *LoopConfig, ipcpCh <-chan IPCPInfo, _ chan<- error) {
	select {
	case info := <-ipcpCh:
		slog.Debug("IPCP negotiation complete", "ip", info.AssignedIP, "ns1", info.NS1, "ns2", info.NS2)
		if cfg.OnIPCP != nil {
			cfg.OnIPCP(info)
		}
	case <-ctx.Done():
	}
}

// extractIPCP inspects a raw PPP packet for an IPCP Configure-Ack containing
// IP address and DNS options.
//
// FortiGate SSL payloads may include the PPP address+control bytes (FF 03)
// before the protocol field, or may omit them — we handle both.
// Protocol 0x8021 = IPCP; code 0x02 = Configure-Ack.
func extractIPCP(pkt []byte) (IPCPInfo, bool) {
	off := 0
	// Skip optional PPP address (0xFF) + control (0x03) bytes
	if len(pkt) >= 2 && pkt[0] == 0xFF && pkt[1] == 0x03 {
		off = 2
	}
	// Need at least: protocol(2) + code(1) + id(1) + length(2) + one option(6)
	if len(pkt) < off+12 {
		return IPCPInfo{}, false
	}
	if pkt[off] != 0x80 || pkt[off+1] != 0x21 { // protocol = IPCP
		return IPCPInfo{}, false
	}
	if pkt[off+2] != 0x02 { // code = Configure-Ack
		return IPCPInfo{}, false
	}

	info := IPCPInfo{}
	// IPCP options start after: protocol(2) + code(1) + id(1) + length(2)
	i := off + 6
	for i+2 <= len(pkt) {
		optType := pkt[i]
		optLen := int(pkt[i+1])
		if optLen < 2 || i+optLen > len(pkt) {
			break
		}
		if optLen == 6 {
			ip := net.IP(pkt[i+2 : i+6]).To4()
			switch optType {
			case 0x03: // IP Address
				info.AssignedIP = ip
			case 0x81: // Primary DNS (RFC 1877)
				info.NS1 = ip
			case 0x83: // Secondary DNS (RFC 1877)
				info.NS2 = ip
			}
		}
		i += optLen
	}

	if info.AssignedIP == nil {
		return IPCPInfo{}, false
	}
	return info, true
}
