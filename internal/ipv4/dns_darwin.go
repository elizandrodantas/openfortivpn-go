//go:build darwin

package ipv4

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"time"
)

// darwinDNS implements DNSManager on macOS the same way the official
// FortiClient (7.4, PrivilegedHelper's installDns/SetResolver, confirmed by
// disassembly) does it, entirely through the SCDynamicStore and without
// touching any file:
//
//  1. Find the primary network service (State:/Network/Global/IPv4
//     PrimaryService) — the physical Wi-Fi/Ethernet service, not the tunnel.
//  2. Back up its Setup:/Network/Service/<id>/DNS entity (normally absent:
//     it's where manually configured DNS lives).
//  3. Write the VPN nameservers (and search domain, if any) there. Setup:
//     takes precedence over the DHCP-provided State: DNS, so the VPN
//     servers become the system's default resolver — for both split and
//     full tunnels, regardless of whether the gateway sends a domain.
//  4. Watch it while connected and re-apply if something overwrites it (a
//     network settings change republishes Setup:) or the primary service
//     changes (e.g. switching Wi-Fi networks).
//  5. On disconnect, restore the backup.
//
// FortiClient keeps its backup in a file; this keeps it in a volatile
// SCDynamicStore key instead (backupKey), so it survives a crash of this
// process but never outlives a reboot — which also clears the override,
// since the dynamic store's Setup: entries are rebuilt from the saved
// network preferences at boot. A backup left behind by a crashed run is
// restored by NewDNSManager.
//
// With --use-pppd, Apple's pppd publishes DNS itself ("usepeerdns" +
// "serviceid", see internal/ppp/pppd_unix.go) whenever the gateway sends DNS
// during IPCP; Add is a no-op then (ipcpProvidedDNS == true).
type darwinDNS struct {
	mu      sync.Mutex
	servers []string
	domain  string
	service string // primary service ID currently overridden; "" if none
	stop    context.CancelFunc
	done    chan struct{}
}

const (
	// backupKey holds the original DNS entity of the overridden service,
	// plus backupServiceKey (its ID) and, if it had none, backupAbsentKey.
	backupKey        = "State:/openfortivpn-go/DNSBackup"
	backupServiceKey = "OpenfortivpnServiceID"
	backupAbsentKey  = "OpenfortivpnAbsent"

	// monitorInterval is how often the override is checked and re-applied.
	monitorInterval = 3 * time.Second
)

// NewDNSManager returns a macOS DNS manager. It first restores any DNS
// override left behind by a previous run that didn't exit cleanly.
func NewDNSManager(_ bool) DNSManager {
	if err := restoreBackup(); err != nil {
		slog.Warn("could not restore DNS left over from a previous session", "err", err)
	}
	return &darwinDNS{}
}

func (d *darwinDNS) Add(_ string, _, ns1, ns2 net.IP, suffix string, ipcpProvidedDNS bool) error {
	if ipcpProvidedDNS {
		// pppd's own usepeerdns+serviceid already published this natively.
		return nil
	}
	var servers []string
	for _, ns := range []net.IP{ns1, ns2} {
		if ns != nil {
			servers = append(servers, ns.String())
		}
	}
	if len(servers) == 0 {
		return fmt.Errorf("ipv4 dns: no nameservers to configure")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.servers, d.domain = servers, suffix

	service, err := primaryService()
	if err != nil {
		return err
	}
	if err := d.override(service); err != nil {
		return err
	}
	slog.Debug("VPN DNS set on primary service", "service", service, "servers", servers, "domain", suffix)

	ctx, cancel := context.WithCancel(context.Background())
	d.stop, d.done = cancel, make(chan struct{})
	go d.monitor(ctx, d.done)
	return nil
}

func (d *darwinDNS) Remove(_, _ net.IP, _ string) error {
	d.mu.Lock()
	stop, done := d.stop, d.done
	d.stop, d.done = nil, nil
	d.mu.Unlock()
	if stop != nil {
		stop()
		<-done
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.service = ""
	err := restoreBackup()
	flushDNSCache()
	return err
}

// override backs up service's Setup: DNS entity (once per session) and
// replaces its nameservers and search domain with the VPN's.
func (d *darwinDNS) override(service string) error {
	if d.service != "" && d.service != service {
		// The primary service changed: give the old one its DNS back first.
		if err := restoreBackup(); err != nil {
			return err
		}
		d.service = ""
	}
	if d.service == "" {
		if err := backup(service); err != nil {
			return err
		}
		d.service = service
	}

	key := setupDNSKey(service)
	var sb strings.Builder
	if exists, err := keyExists(key); err != nil {
		return err
	} else if exists {
		fmt.Fprintf(&sb, "get %s\n", key) // keep any other fields it has
	} else {
		sb.WriteString("d.init\n")
	}
	fmt.Fprintf(&sb, "d.add ServerAddresses * %s\n", strings.Join(d.servers, " "))
	if d.domain != "" {
		fmt.Fprintf(&sb, "d.add SearchDomains * %s\n", d.domain)
	}
	fmt.Fprintf(&sb, "set %s\n", key)
	if _, err := scutil(sb.String()); err != nil {
		return fmt.Errorf("ipv4 dns: set %s: %w", key, err)
	}
	flushDNSCache()
	return nil
}

// monitor re-applies the override whenever it's lost: the primary service
// changed, or the system rewrote its Setup: DNS entity.
func (d *darwinDNS) monitor(ctx context.Context, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(monitorInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.mu.Lock()
		if err := d.check(); err != nil {
			slog.Warn("could not re-apply VPN DNS", "err", err)
		}
		d.mu.Unlock()
	}
}

func (d *darwinDNS) check() error {
	service, err := primaryService()
	if err != nil {
		return err // e.g. no network at all right now; retry next tick
	}
	if service == d.service {
		out, err := scutil(fmt.Sprintf("show %s\n", setupDNSKey(service)))
		if err != nil {
			return err
		}
		if slices.Equal(arrayValues(out, "ServerAddresses"), d.servers) {
			return nil
		}
		slog.Info("VPN DNS was overwritten, re-applying", "service", service)
	} else {
		slog.Info("primary network service changed, moving VPN DNS", "from", d.service, "to", service)
	}
	return d.override(service)
}

func setupDNSKey(service string) string {
	return "Setup:/Network/Service/" + service + "/DNS"
}

// primaryService returns the ID of the current primary network service.
func primaryService() (string, error) {
	out, err := scutil("show State:/Network/Global/IPv4\n")
	if err != nil {
		return "", err
	}
	if id := dictValue(out, "PrimaryService"); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("ipv4 dns: no primary network service")
}

// backup saves service's current Setup: DNS entity into backupKey, unless a
// backup already exists (it is the original; never overwrite it with our
// own override).
func backup(service string) error {
	if exists, err := keyExists(backupKey); err != nil || exists {
		return err
	}
	key := setupDNSKey(service)
	exists, err := keyExists(key)
	if err != nil {
		return err
	}
	var sb strings.Builder
	if exists {
		fmt.Fprintf(&sb, "get %s\n", key)
	} else {
		sb.WriteString("d.init\n")
		fmt.Fprintf(&sb, "d.add %s # 1\n", backupAbsentKey)
	}
	fmt.Fprintf(&sb, "d.add %s %s\n", backupServiceKey, service)
	fmt.Fprintf(&sb, "set %s\n", backupKey)
	if _, err := scutil(sb.String()); err != nil {
		return fmt.Errorf("ipv4 dns: back up %s: %w", key, err)
	}
	return nil
}

// restoreBackup puts back the DNS entity saved by backup, if any.
func restoreBackup() error {
	out, err := scutil(fmt.Sprintf("show %s\n", backupKey))
	if err != nil {
		return err
	}
	service := dictValue(out, backupServiceKey)
	if service == "" {
		return nil // no backup: nothing to restore
	}
	key := setupDNSKey(service)
	var sb strings.Builder
	if dictValue(out, backupAbsentKey) != "" {
		fmt.Fprintf(&sb, "remove %s\n", key)
	} else {
		fmt.Fprintf(&sb, "get %s\n", backupKey)
		fmt.Fprintf(&sb, "d.remove %s\n", backupServiceKey)
		fmt.Fprintf(&sb, "set %s\n", key)
	}
	fmt.Fprintf(&sb, "remove %s\n", backupKey)
	if _, err := scutil(sb.String()); err != nil {
		return fmt.Errorf("ipv4 dns: restore %s: %w", key, err)
	}
	slog.Debug("restored original DNS", "service", service)
	return nil
}

func keyExists(key string) (bool, error) {
	out, err := scutil(fmt.Sprintf("show %s\n", key))
	if err != nil {
		return false, err
	}
	return !strings.Contains(out, "No such key"), nil
}

// scutil runs a script of scutil commands against the SCDynamicStore.
// scutil exits 0 even when a command fails, printing e.g. "Permission
// denied" instead, so its output is checked too ("No such key" is not an
// error: it's how a missing key reads).
func scutil(script string) (string, error) {
	cmd := exec.Command("scutil")
	cmd.Stdin = strings.NewReader(script + "quit\n")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("scutil: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	for _, failure := range []string{"Permission denied", "failed", "Invalid", "invalid"} {
		if strings.Contains(string(out), failure) {
			return "", fmt.Errorf("scutil: %s", strings.TrimSpace(string(out)))
		}
	}
	return string(out), nil
}

// dictValue returns a top-level scalar from scutil's dictionary output
// ("  Key : value"), or "".
func dictValue(out, key string) string {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), " : ")
		if ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// arrayValues returns the elements of an array in scutil's dictionary
// output ("  Key : <array> {" / "    0 : value" / "  }").
func arrayValues(out, key string) []string {
	var vals []string
	in := false
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !in {
			in = line == key+" : <array> {"
			continue
		}
		if line == "}" {
			break
		}
		if _, v, ok := strings.Cut(line, " : "); ok {
			vals = append(vals, strings.TrimSpace(v))
		}
	}
	return vals
}

// flushDNSCache asks mDNSResponder to reload its config immediately instead
// of waiting for its own poll interval.
func flushDNSCache() {
	_ = exec.Command("dscacheutil", "-flushcache").Run()
	_ = exec.Command("killall", "-HUP", "mDNSResponder").Run()
}
