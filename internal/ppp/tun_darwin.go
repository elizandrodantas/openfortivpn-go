//go:build darwin

package ppp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/elizandrodantas/openfortivpn-go/internal/config"
)

const (
	utunControlName = "com.apple.net.utun_control"
	sysprotoControl = 2 // SYSPROTO_CONTROL, <sys/sys_domain.h>
	utunOptIfname   = 2 // UTUN_OPT_IFNAME, <net/if_utun.h>
	// utunHeaderLen is the 4-byte protocol-family prefix utun puts in front
	// of every packet read from or written to its control socket.
	utunHeaderLen = 4
)

// Start launches the PPP session. By default it uses the userspace PPP
// engine over a native utun interface, which keeps the legacy
// com.apple.nke.ppp kernel extension (driven by the system pppd) entirely
// out of the data path — that kext has been observed to panic the kernel
// inside its own packet handling during otherwise-normal operation.
// cfg.UsePPPD restores the old pppd-over-PTY behavior.
func Start(cfg *config.Config) (Process, error) {
	if cfg.UsePPPD {
		return startPPPD(cfg)
	}
	if cfg.PPPDIfname != "" {
		slog.Warn("pppd-ifname is ignored with the utun backend (the kernel picks the utun name); use --use-pppd to keep it")
	}
	dev, err := openUtun()
	if err != nil {
		return nil, err
	}
	slog.Debug("utun interface created", "iface", dev.Name())
	return startEngine(dev), nil
}

// utunDevice implements tunDevice on a macOS utun control socket.
type utunDevice struct {
	file *os.File
	name string
	rbuf []byte
}

// openUtun creates a new utunN interface (the kernel picks N). Requires
// root.
func openUtun() (*utunDevice, error) {
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("ppp: utun socket (are you running as root?): %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd) //nolint:errcheck
		}
	}()

	info := &unix.CtlInfo{}
	copy(info.Name[:], utunControlName)
	if err := unix.IoctlCtlInfo(fd, info); err != nil {
		return nil, fmt.Errorf("ppp: utun CTLIOCGINFO: %w", err)
	}
	// Unit 0 lets the kernel allocate the next free utunN.
	if err := unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: 0}); err != nil {
		return nil, fmt.Errorf("ppp: utun connect: %w", err)
	}
	name, err := unix.GetsockoptString(fd, sysprotoControl, utunOptIfname)
	if err != nil {
		return nil, fmt.Errorf("ppp: utun get ifname: %w", err)
	}
	// Non-blocking + os.NewFile registers the fd with Go's runtime poller,
	// so Close() reliably unblocks a pending Read.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, fmt.Errorf("ppp: utun set nonblock: %w", err)
	}
	unix.CloseOnExec(fd)

	ok = true
	name = strings.TrimRight(name, "\x00")
	return &utunDevice{
		file: os.NewFile(uintptr(fd), name),
		name: name,
		rbuf: make([]byte, utunHeaderLen+65535),
	}, nil
}

func (d *utunDevice) Name() string { return d.name }

// ReadPacket returns the next IPv4 packet, skipping any other family (the
// OS may route IPv6 onto the interface, which this tunnel doesn't carry).
// Cancellation is driven by Close, which unblocks the pending Read.
func (d *utunDevice) ReadPacket(_ context.Context) ([]byte, error) {
	for {
		n, err := d.file.Read(d.rbuf)
		if err != nil {
			return nil, err
		}
		ip, ok := stripUtunHeader(d.rbuf[:n])
		if !ok {
			continue
		}
		return ip, nil
	}
}

func (d *utunDevice) WritePacket(ip []byte) error {
	_, err := d.file.Write(addUtunHeader(ip))
	return err
}

// SetAddress configures the interface as a point-to-point link, the same
// shape pppd gives a pppN interface.
func (d *utunDevice) SetAddress(local, peer net.IP, mtu int) error {
	args := []string{d.name, "inet", local.String(), peer.String(),
		"netmask", "255.255.255.255", "mtu", strconv.Itoa(mtu), "up"}
	out, err := exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ifconfig %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Close closes the control socket; the kernel destroys the utun interface
// (and its routes) along with it.
func (d *utunDevice) Close() error {
	return d.file.Close()
}

// stripUtunHeader returns the IPv4 payload of a packet read from utun, or
// ok=false if it's too short or not AF_INET.
func stripUtunHeader(pkt []byte) (ip []byte, ok bool) {
	if len(pkt) <= utunHeaderLen {
		return nil, false
	}
	if binary.BigEndian.Uint32(pkt[:utunHeaderLen]) != unix.AF_INET {
		return nil, false
	}
	return pkt[utunHeaderLen:], true
}

// addUtunHeader prepends the AF_INET family prefix utun expects on write.
func addUtunHeader(ip []byte) []byte {
	out := make([]byte, utunHeaderLen+len(ip))
	binary.BigEndian.PutUint32(out[:utunHeaderLen], unix.AF_INET)
	copy(out[utunHeaderLen:], ip)
	return out
}
