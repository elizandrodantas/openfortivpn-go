//go:build windows

// On Windows there is no pppd daemon available, so the userspace PPP engine
// (engine.go) drives a wintun virtual TUN adapter instead.
package ppp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
	"github.com/elizandrodantas/openfortivpn-go/internal/ppp/wintundll"
)

const (
	defaultAdapterName = "openfortivpn"
	ringCapacity       = wintun.RingCapacityMin // 128 KiB; must be a power of two
	waitPollInterval   = 200 * time.Millisecond
)

// Start creates a wintun adapter and launches the negotiation + relay engine
// in the background. Requires Administrator privileges (driver
// install/adapter creation).
func Start(cfg *config.Config) (Process, error) {
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

	return startEngine(&wintunDevice{adapter: adapter, session: session, name: name}), nil
}

// wintunDevice implements tunDevice on a wintun adapter session.
type wintunDevice struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
}

func (d *wintunDevice) Name() string { return d.name }

func (d *wintunDevice) ReadPacket(ctx context.Context) ([]byte, error) {
	waitEvent := d.session.ReadWaitEvent()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		packet, err := d.session.ReceivePacket()
		if err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				// Nothing pending — wait briefly (bounded so ctx
				// cancellation is still observed promptly) then retry.
				_, _ = windows.WaitForSingleObject(waitEvent, uint32(waitPollInterval/time.Millisecond))
				continue
			}
			return nil, fmt.Errorf("wintun receive packet: %w", err)
		}
		// The ring slot must be released before the next receive, so hand
		// the caller its own copy.
		out := make([]byte, len(packet))
		copy(out, packet)
		d.session.ReleaseReceivePacket(packet)
		return out, nil
	}
}

func (d *wintunDevice) WritePacket(ip []byte) error {
	buf, err := d.session.AllocateSendPacket(len(ip))
	if err != nil {
		return err
	}
	copy(buf, ip)
	d.session.SendPacket(buf)
	return nil
}

// SetAddress assigns the negotiated local IP to the adapter as a /32
// (matching classic point-to-point PPP semantics — actual routing is handled
// separately by internal/ipv4/route_windows.go). The peer address and MTU
// aren't needed by wintun.
func (d *wintunDevice) SetAddress(local, _ net.IP, _ int) error {
	args := []string{"interface", "ip", "set", "address",
		"name=" + d.name, "source=static",
		"addr=" + local.String(), "mask=255.255.255.255",
	}
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh set address: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (d *wintunDevice) Close() error {
	d.session.End()
	return d.adapter.Close()
}
