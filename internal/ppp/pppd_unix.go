//go:build !windows

package ppp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/elizandrodantas/openfortivpn-go/internal/config"
)

// pidFilePath tracks the pppd child we launched, so a crashed or SIGKILLed
// run of this program can find and clean up an orphaned pppd left behind
// from a previous session before starting a new one.
const pidFilePath = "/var/run/openfortivpn-go.pppd.pid"

// pppdSignature lists argument substrings that are always present in the
// pppd command line we build (see buildArgs), used to confirm a PID found in
// the pidfile is actually our pppd and not an unrelated process that reused
// the PID.
var pppdSignature = []string{"230400", ":169.254.2.1", "lcp-max-configure"}

// Process wraps a running pppd subprocess and its PTY master.
type Process struct {
	cmd       *exec.Cmd
	master    *os.File
	closeOnce sync.Once

	// waitDone is closed exactly once, after cmd.Wait() returns, by the
	// reaper goroutine started in Start(). Close() and Wait() both read
	// from this instead of calling cmd.Wait() themselves, since Cmd.Wait
	// must only ever be called once and both methods need to observe the
	// same "has pppd actually exited yet" state.
	waitDone chan struct{}
	waitErr  error
}

// PTY returns the PTY master file, used by the I/O relay goroutines.
func (p *Process) PTY() *os.File {
	return p.master
}

// Start launches pppd with the appropriate arguments derived from cfg.
// It uses a PTY (pseudo-terminal) to communicate with pppd.
func Start(cfg *config.Config) (*Process, error) {
	if err := cleanupOrphan(); err != nil {
		slog.Warn("orphaned pppd cleanup failed", "err", err)
	}

	args := buildArgs(cfg)
	slog.Debug("starting pppd", "args", args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = os.Environ()
	if cfg.PPPDIPParam != "" {
		cmd.Env = append(cmd.Env, "IPPARAM="+cfg.PPPDIPParam)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	master, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("ppp: start pppd: %w", err)
	}
	if err := os.WriteFile(pidFilePath, []byte(strconv.Itoa(cmd.Process.Pid)), 0644); err != nil {
		slog.Warn("could not write pppd pid file", "path", pidFilePath, "err", err)
	}

	p := &Process{cmd: cmd, master: master, waitDone: make(chan struct{})}
	go func() {
		p.waitErr = cmd.Wait()
		close(p.waitDone)
	}()
	return p, nil
}

// Wait waits for pppd to exit, respecting context cancellation.
func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-p.waitDone:
		return interpretExitError(p.waitErr)
	case <-ctx.Done():
		p.cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
		select {
		case <-p.waitDone:
		case <-time.After(3 * time.Second):
			p.cmd.Process.Kill() //nolint:errcheck
			<-p.waitDone
		}
		return ctx.Err()
	}
}

// Close terminates pppd and closes the PTY master. Safe to call multiple times.
//
// It waits for pppd to actually exit before closing the PTY master. pppd's
// SIGTERM handler runs its own LCP/IPCP "down" negotiation and kernel-level
// detach ioctls against the PPP unit attached to this tty; closing the master
// concurrently with that independently triggers the kernel tty layer's own
// hang-up notification to the same PPP line discipline. Two independent
// teardown paths racing the same kernel PPP state is the kind of
// double-teardown that can wedge or crash the legacy com.apple.nke.ppp kext
// on macOS, so we let pppd finish exiting on its own (escalating to SIGKILL
// only if it doesn't) before severing the tty.
func (p *Process) Close() {
	p.closeOnce.Do(func() {
		if p.cmd.Process != nil {
			p.cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
			select {
			case <-p.waitDone:
			case <-time.After(3 * time.Second):
				p.cmd.Process.Kill() //nolint:errcheck
				select {
				case <-p.waitDone:
				case <-time.After(3 * time.Second):
					slog.Warn("pppd did not exit after SIGKILL, closing PTY anyway")
				}
			}
		}
		p.master.Close()
		os.Remove(pidFilePath) //nolint:errcheck
	})
}

// cleanupOrphan looks for a pppd left running by a previous, non-gracefully
// terminated run of this program (crash, SIGKILL, abrupt system sleep) and
// terminates it before a new pppd is started. Two overlapping pppd sessions
// racing for the same kernel-level PPP link is exactly the kind of anomalous
// state that can be involved in wedging legacy OS PPP support, so we avoid it
// proactively rather than relying on the OS to arbitrate it.
func cleanupOrphan() error {
	data, err := os.ReadFile(pidFilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		os.Remove(pidFilePath) //nolint:errcheck
		return nil
	}

	if syscall.Kill(pid, 0) != nil {
		// Process no longer exists; stale pidfile from a clean exit that
		// didn't get to remove it (or an already-reaped crash).
		os.Remove(pidFilePath) //nolint:errcheck
		return nil
	}

	if !isOurPPPD(pid) {
		// The PID was recycled by an unrelated process; do not touch it.
		os.Remove(pidFilePath) //nolint:errcheck
		return nil
	}

	slog.Warn("found orphaned pppd from a previous session, terminating", "pid", pid)
	syscall.Kill(pid, syscall.SIGTERM) //nolint:errcheck
	for i := 0; i < 30; i++ {
		if syscall.Kill(pid, 0) != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if syscall.Kill(pid, 0) == nil {
		slog.Warn("orphaned pppd did not exit on SIGTERM, sending SIGKILL", "pid", pid)
		syscall.Kill(pid, syscall.SIGKILL) //nolint:errcheck
	}
	os.Remove(pidFilePath) //nolint:errcheck
	return nil
}

// isOurPPPD confirms a PID is actually a pppd instance we launched, by
// checking its command line for a set of argument substrings that are
// always present in buildArgs' output. This guards against killing an
// unrelated process that happens to reuse a recycled PID.
func isOurPPPD(pid int) bool {
	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "command=").Output()
	if err != nil {
		return false
	}
	cmdline := string(out)
	if !strings.Contains(cmdline, "pppd") {
		return false
	}
	for _, sig := range pppdSignature {
		if !strings.Contains(cmdline, sig) {
			return false
		}
	}
	return true
}

// buildArgs constructs the pppd command-line arguments from cfg.
func buildArgs(cfg *config.Config) []string {
	pppd := "pppd"
	args := []string{
		pppd,
		"230400",
		":169.254.2.1",
		"noipdefault",
		"ipcp-accept-local",
		"noaccomp",
		"noauth",
		"default-asyncmap",
		"nopcomp",
		"receive-all",
		"nodefaultroute",
		"nodetach",
		"lcp-max-configure", "40",
		"mru", "1354",
	}

	if cfg.PPPDIfname != "" {
		args = append(args, "ifname", cfg.PPPDIfname)
	}
	usePeerDNS := cfg.PPPDUsePeerDNS
	// On macOS, Apple's own pppd has built-in SystemConfiguration
	// integration (see internal/ipv4/dns_darwin.go for the investigation):
	// "usepeerdns" + "serviceid" makes pppd itself publish DNS/IPv4 into
	// the SCDynamicStore under a service id, using its own Apple-signed
	// code path rather than our unsigned binary poking scutil directly.
	if runtime.GOOS == "darwin" && cfg.SetDNS {
		usePeerDNS = true
		args = append(args, "serviceid", "openfortivpn")
	}
	if usePeerDNS {
		args = append(args, "usepeerdns")
	}
	if cfg.PPPDLog != "" {
		args = append(args, "logfile", cfg.PPPDLog)
	}
	if cfg.PPPDPlugin != "" {
		args = append(args, "plugin", cfg.PPPDPlugin)
	}
	if cfg.PPPDCall != "" {
		args = append(args, "call", cfg.PPPDCall)
	}
	if cfg.PPPDAcceptRemote {
		args = append(args, "ipcp-accept-remote")
	}

	return args
}

func interpretExitError(err error) error {
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if ok := false; !ok {
		_ = exitErr
	}
	// Exit code 16 = pppd received SIGTERM (normal shutdown)
	if exit, ok := err.(*exec.ExitError); ok {
		if exit.ExitCode() == 16 {
			return nil
		}
		slog.Warn("pppd exited with non-zero code", "code", exit.ExitCode())
	}
	return err
}
