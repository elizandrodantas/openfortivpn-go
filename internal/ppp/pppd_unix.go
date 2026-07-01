//go:build !windows

package ppp

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/elizandrodantas/openfortivpn-go/internal/config"
)

// Process wraps a running pppd subprocess and its PTY master.
type Process struct {
	cmd        *exec.Cmd
	master     *os.File
	closeOnce  sync.Once
}

// PTY returns the PTY master file, used by the I/O relay goroutines.
func (p *Process) PTY() *os.File {
	return p.master
}

// Start launches pppd with the appropriate arguments derived from cfg.
// It uses a PTY (pseudo-terminal) to communicate with pppd.
func Start(cfg *config.Config) (*Process, error) {
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
	return &Process{cmd: cmd, master: master}, nil
}

// Wait waits for pppd to exit, respecting context cancellation.
func (p *Process) Wait(ctx context.Context) error {
	done := make(chan error, 1)
	go func() {
		done <- p.cmd.Wait()
	}()
	select {
	case err := <-done:
		return interpretExitError(err)
	case <-ctx.Done():
		p.cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			p.cmd.Process.Kill() //nolint:errcheck
			<-done
		}
		return ctx.Err()
	}
}

// Close terminates pppd and closes the PTY master. Safe to call multiple times.
func (p *Process) Close() {
	p.closeOnce.Do(func() {
		if p.cmd.Process != nil {
			p.cmd.Process.Signal(syscall.SIGTERM) //nolint:errcheck
		}
		p.master.Close()
	})
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
