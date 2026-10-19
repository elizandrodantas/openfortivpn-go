# openfortivpn-go

A modern, dependency-light **Go rewrite of [openfortivpn](https://github.com/adrienverge/openfortivpn)** — a client for PPP+SSL VPN tunnel services used by Fortinet's FortiGate/FortiClient VPN gateways.

This project is **not affiliated with Fortinet**. It is a fork/reimplementation of the original C client, rebuilt from scratch in Go. It follows the same wire protocol and reuses the system's `pppd` the same way the original does, while adding a few quality-of-life features that the C client doesn't have (see [Features](#features) below).

> Credit where it's due: all protocol reverse-engineering and the original design come from [adrienverge/openfortivpn](https://github.com/adrienverge/openfortivpn) and its contributors. This project would not exist without their work. See [Acknowledgements](#acknowledgements).

## Table of contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration file](#configuration-file)
- [Building from source](#building-from-source)
- [Architecture](#architecture)
- [Known limitations](#known-limitations)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Features

### Authentication

- **Username/password** — standard FortiGate `logincheck` flow, including realm support (`--realm`).
- **Two-factor authentication (2FA)**:
  - **FortiToken Mobile push** — detected and handled automatically; the client waits for you to approve the push notification on your phone (optionally delayed via `otp-delay` in the config file).
  - **Manual OTP** — if no push is available, you're prompted for a one-time code, or you can pass it directly with `--otp`.
- **Cookie-based reuse** — reconnect instantly with a previously obtained `SVPNCOOKIE` value via `--cookie`, skipping the interactive login entirely (handy for scripting or fast reconnects).
- **SAML browser login** — for gateways configured with SAML SSO, `--saml-login <port>` spins up a local callback server, prints a login URL to open in your browser, and completes authentication once the identity provider redirects back.
- **Secure password entry**:
  - Hidden terminal input (no echo) by default.
  - Optional integration with any `pinentry` program (`--pinentry <path>`) — useful for GUI-based password entry or when scripting Assuan-protocol pinentry front-ends.

### TLS

- **Certificate pinning** — trust specific gateway certificates by SHA-256 fingerprint with `--trusted-cert <digest>` (repeatable), independent of the system trust store. If verification fails, the client prints the presented certificate's digest so you can copy it straight into `--trusted-cert`.
- **Custom CA** — verify against a specific CA bundle with `--ca-file`.
- **Client certificate authentication** — PEM certificate/key pairs (`--user-cert` / `--user-key`, optionally password-protected via `--pem-passphrase`), or PKCS#11 smartcard/HSM tokens using a `pkcs11:` URI as the `--user-cert` value.
- **TLS version control** — set a minimum accepted TLS version with `--min-tls` (`1.0`–`1.3`; defaults to `1.2`), or configure the cipher list with `--cipher-list`.
- **`--insecure-ssl`** — disable all certificate verification (only for lab/debugging use).
- **HTTP(S) proxy support** — connects through an upstream proxy automatically if `HTTPS_PROXY`/`https_proxy`/`ALL_PROXY`/`all_proxy` is set in the environment, using an HTTP `CONNECT` tunnel.

### Routing

- **Full-tunnel by default** — replaces the system default route with one via the VPN interface, while always keeping a direct host route to the gateway itself so the TLS session doesn't get routed through itself.
- **Automatic split-tunneling** — if the FortiGate gateway supplies split-tunnel routes in its configuration, only those subnets are routed through the VPN; your existing default route is left untouched.
- **`--half-internet-routes`** — an alternative full-tunnel strategy that adds two `/1` routes (`0.0.0.0/1` and `128.0.0.0/1`) instead of replacing the default route directly (avoids clobbering a DHCP-managed default route on some systems).
- **`--no-routes`** — disable all routing table changes and manage routes yourself.

### DNS

DNS handling is implemented per-platform to match each OS's native mechanisms as closely as possible:

- **Linux** — updates `/etc/resolv.conf` directly (with automatic backup/restore of the original file), or delegates to `resolvconf` if available (`--pppd-use-peerdns` / `use-resolvconf` in the config file).
- **Windows** — configures DNS servers on the PPP interface via `netsh interface ip set/add dns`, restoring DHCP-sourced DNS on disconnect.
- **macOS** — configures DNS the same way the official FortiClient does, entirely through the `SCDynamicStore` and without writing any file: the VPN nameservers (and search domain, if the gateway sends one) are set on the primary network service's `Setup:` DNS entity — the same place manually configured DNS lives — so they become the system's default resolver on both split and full tunnels. The original value is backed up in a volatile `SCDynamicStore` key, re-applied if the system overwrites it or the primary service changes (e.g. switching Wi-Fi networks), and restored on disconnect (or on the next start, after a crash). With `--use-pppd`, Apple's `pppd` publishes DNS itself (via `usepeerdns` + a registered `serviceid`) whenever the gateway hands out DNS during IPCP. The DNS cache is flushed (`dscacheutil` + `mDNSResponder`) after any change.
- **`--no-dns`** — disable all DNS configuration changes.

### Reliability & operations

- **Persistent reconnection** — `--persistent <seconds>` automatically reconnects after a disconnect instead of exiting, with a configurable delay between attempts.
- **Clean shutdown** — `Ctrl+C` (SIGINT), SIGTERM, or SIGHUP (e.g. closing the terminal window the process is attached to) tear down routes/DNS and terminate `pppd` gracefully before the process exits.
- **Orphaned `pppd` cleanup (Unix)** — the PID of the launched `pppd` is tracked in `/var/run/openfortivpn-go.pppd.pid`. If a previous run was killed non-gracefully (`kill -9`, crash, abrupt system sleep) and left `pppd` running, the next run detects and terminates it before starting a new session — avoiding two PPP sessions competing for the same OS-level PPP link.
- **macOS: no `pppd`, no PPP kernel extension** — by default the client negotiates PPP itself (the same LCP/IPCP engine used on Windows, `internal/ppp/pppproto`) and carries IPv4 over a native `utun` interface. Apple's `pppd` drives the legacy `com.apple.nke.ppp` kext, which has been observed to panic the kernel from inside its own packet handling (`Break 0x5519 ... Panic (by design)`, a bounds-check trap, with `com.apple.nke.ppp` in "Kernel Extensions in backtrace") during otherwise-normal use; the utun backend keeps that kext out of the data path entirely. `--use-pppd` / `use-pppd = true` restores the old `pppd`-over-PTY behavior, including a `caffeinate -s -w <pid>` idle-sleep assertion for the lifetime of the tunnel, `--pppd-log`, and `--pppd-extra-arg` to pass raw argv tokens to `pppd` (an option and its value each need their own occurrence, e.g. `--pppd-extra-arg mru --pppd-extra-arg 1500`).
- **Configuration file** — every CLI flag has an equivalent config-file key, using the same INI-style format and default path (`/etc/openfortivpn/config`) as the original client. See [Configuration file](#configuration-file).
- **Flexible logging**:
  - `-v` / `-vv` / `-vvv` — progressively more verbose console output.
  - `-q` / `--quiet` — errors only.
  - `--log-file <path>` — always writes complete DEBUG-level logs (full request/response bodies and XML, untruncated) to a file, independent of the console verbosity — useful for filing detailed bug reports without cluttering your terminal.

### Cross-platform builds

Single static binaries for:

| OS | Architectures |
|---|---|
| Linux | amd64, arm64, arm |
| macOS | amd64 (Intel), arm64 (Apple Silicon) |
| Windows | amd64, arm64 |

## Requirements

- A system `pppd` binary on **Linux** (openfortivpn-go shells out to it, matching the original client's architecture) — e.g. `apt install ppp` / `dnf install ppp`. **macOS** needs nothing extra: it uses a built-in PPP engine over `utun` by default (and the system `pppd`, shipped with macOS, only with `--use-pppd`).
- **Windows** needs no separate driver install: if `wintun.dll` (the [`wintun`](https://www.wintun.net/) driver — the same one WireGuard/Tailscale use) isn't already present next to the executable or in `System32`, it's downloaded automatically on first run for the correct architecture, with its checksum verified before use. Requires internet access on first run; place a trusted copy of `wintun.dll` next to the executable yourself to skip the download entirely.
- **Root/administrator privileges** — required to run `pppd` (or create the `utun`/`wintun` interface on macOS/Windows), modify the routing table, and change DNS configuration. Run with `sudo` on Linux/macOS or an elevated shell on Windows.

## Installation

### Go install

```sh
go install github.com/elizandrodantas/openfortivpn-go/cmd/openfortivpn@latest
```

### Prebuilt binaries

Download the binary for your OS/architecture from the [Releases](https://github.com/elizandrodantas/openfortivpn-go/releases) page. Each release's notes list every change since the previous tag, grouped by type (see [Contributing](#contributing) for how those are generated).

### Build from source

See [Building from source](#building-from-source).

## Usage

```sh
sudo openfortivpn vpn.example.com:443 --username alice
```

If you omit `--host`/`--port`, you can instead pass `host[:port]` as a positional argument (as above). All flags below can also be set via the [configuration file](#configuration-file); CLI flags always take precedence.

### Examples

```sh
# Interactive password + OTP prompt
sudo openfortivpn vpn.example.com --username alice

# Password and OTP supplied non-interactively
sudo openfortivpn vpn.example.com -u alice -p 'hunter2' --otp 123456

# Reuse a previously obtained session cookie (no interactive login)
sudo openfortivpn vpn.example.com --cookie 'AbCdEf0123...'

# SAML SSO login via local browser callback on port 8020
sudo openfortivpn vpn.example.com --saml-login 8020

# Pin the gateway certificate instead of trusting the system CA store
sudo openfortivpn vpn.example.com -u alice --trusted-cert 3f1e...c9

# Full debug log to file, quiet console
sudo openfortivpn vpn.example.com -u alice -q --log-file /tmp/openfortivpn.log

# Auto-reconnect every 10 seconds after a disconnect
sudo openfortivpn vpn.example.com -u alice --persistent 10
```

### Flag reference

| Flag | Shorthand | Description |
|---|---|---|
| `--config <path>` | `-c` | Config file path (default: `/etc/openfortivpn/config`) |
| `--verbose` | `-v` | Increase verbosity; repeat for more detail (`-v`, `-vv`, `-vvv`) |
| `--quiet` | `-q` | Suppress non-error output |
| `--host <host>` | | VPN gateway hostname |
| `--port <port>` | | VPN gateway port |
| `--timeout <seconds>` | | Connect timeout for TCP+TLS (default `20`; `0` = no timeout) |
| `--username <user>` | `-u` | Username |
| `--password <pass>` | `-p` | Password (omit to be prompted interactively) |
| `--otp <code>` | | One-time password / 2FA code |
| `--cookie <value>` | | Reuse an existing `SVPNCOOKIE` session, bypassing login |
| `--saml-login <port>` | | Enable SAML browser-based login on the given local port |
| `--realm <realm>` | | Authentication realm |
| `--sni <hostname>` | | Override the TLS SNI hostname sent to the gateway |
| `--ifname <name>` | | Bind to a specific local network interface |
| `--pinentry <path>` | | Path to a `pinentry` binary for secure password entry |
| `--force-login` | | When the gateway only allows one session per user (`limit-user-logins`), disconnect the other open session without asking |
| `--ca-file <path>` | | Custom CA certificate bundle |
| `--user-cert <path>` | | Client certificate (PEM path, or `pkcs11:...` URI) |
| `--user-key <path>` | | Client private key file |
| `--pem-passphrase <pass>` | | Passphrase for an encrypted private key |
| `--insecure-ssl` | | Disable TLS certificate verification (dangerous) |
| `--min-tls <ver>` | | Minimum TLS version: `1.0`, `1.1`, `1.2` (default), `1.3` |
| `--seclevel-1` | | Use OpenSSL SECLEVEL=1 semantics for weak Diffie-Hellman parameters |
| `--cipher-list <list>` | | TLS cipher list |
| `--trusted-cert <sha256>` | | Pin a trusted certificate by SHA-256 digest (repeatable) |
| `--no-routes` | | Do not modify the routing table |
| `--no-dns` | | Do not modify DNS configuration |
| `--half-internet-routes` | | Use `0.0.0.0/1` + `128.0.0.0/1` instead of replacing the default route |
| `--use-pppd` | | macOS: use the system `pppd` (legacy `com.apple.nke.ppp` kext) instead of the built-in PPP engine over `utun` |
| `--pppd-use-peerdns` | | Ask `pppd` to configure DNS itself |
| `--pppd-log <path>` | | `pppd` log file |
| `--pppd-plugin <path>` | | `pppd` plugin path |
| `--pppd-ifname <name>` | | `pppd` interface name |
| `--pppd-call <path>` | | `pppd` call file |
| `--pppd-accept-remote` | | Accept the remote IP address offered by `pppd` |
| `--pppd-extra-arg <arg>` | | Extra raw argv token passed to `pppd` verbatim (repeatable; an option and its value each need their own `--pppd-extra-arg`, e.g. `--pppd-extra-arg mru --pppd-extra-arg 1500` — for diagnostics, without a rebuild) |
| `--persistent <seconds>` | | Reconnect automatically after this many seconds (`0` = disabled) |
| `--log-file <path>` | | Write full DEBUG-level logs to this file regardless of `-v` |
| `--version` | | Print the client version |
| `--help` | `-h` | Show help |

## Configuration file

By default, `openfortivpn` reads `/etc/openfortivpn/config` (override with `-c`/`--config`). It's missing that file entirely is fine — you'll just need to pass everything via flags. The format is INI-style: `key = value` (or `key=value`), `#` starts a comment, blank lines are ignored, and unknown keys are a hard error.

```ini
# /etc/openfortivpn/config
host = vpn.example.com
port = 443
username = alice
password = hunter2
otp-prompt = Enter your FortiToken code:
otp-delay = 5
no-ftm-push = false
force-login = false

realm = corp
sni = vpn.example.com

set-routes = true
set-dns = true
half-internet-routes = false
persistent = 10

use-syslog = false
use-resolvconf = false

use-pppd = false
pppd-use-peerdns = false
pppd-log = /var/log/pppd.log
pppd-plugin =
pppd-ipparam =
pppd-ifname =
pppd-call =
pppd-accept-remote = false
# pppd-extra-arg = mru        (repeatable; one raw argv token per line —
# pppd-extra-arg = 1500        an option and its value need two entries, since
#                               each becomes a separate pppd argv element)

ca-file =
user-cert =
user-key =
pem-passphrase =
insecure-ssl = false
min-tls = 1.2
seclevel-1 = false
cipher-list =
trusted-cert = 3f1e9c2a5b7d...c9

saml-login = 8020
user-agent =
hostcheck =
check-virtual-desktop =
```

Notes:
- Boolean values accept `1`/`true`/`yes` and `0`/`false`/`no` (case-insensitive).
- `trusted-cert` may be repeated (one line per pinned digest).
- `cookie` (and `cookie-on-stdin`) are **intentionally ignored** in the config file — a session cookie must always be supplied via `--cookie` on the command line, so it's never persisted to disk.

## Building from source

Requires Go (see `go.mod` for the minimum version) and `make`.

```sh
make build   # build for the current OS/architecture -> ./openfortivpn
make dist    # cross-compile for all supported OS/architecture pairs -> ./dist/
make test    # go test -race ./...
make lint    # go vet + staticcheck
make clean   # remove build artifacts
make help    # list all targets
```

`make dist` produces binaries for: `linux/amd64`, `linux/arm64`, `linux/arm`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`, `windows/arm64`.

The version string embedded in binaries (visible via `--version`) is derived from `git describe --tags --always --dirty`, or can be overridden explicitly: `make build VERSION=v1.2.3`.

## Architecture

| Package | Responsibility |
|---|---|
| `cmd/openfortivpn` | CLI entrypoint (Cobra): flag parsing, logging setup, signal handling |
| `internal/config` | Config struct, INI file loader, validation |
| `internal/auth` | Authentication strategies: password/OTP/FTM push, cookie, SAML |
| `internal/tlsconn` | TLS connection setup, proxy support, certificate verification/pinning |
| `internal/httptunnel` | Minimal hand-rolled HTTP client over the raw TLS socket, plus the local SAML callback server |
| `internal/tunnel` | Top-level orchestration: connect → auth → XML config → pppd → relay → routes/DNS |
| `internal/xmlparse` | Lenient parser for the gateway's `fortisslvpn_xml` response (assigned IP, DNS, split routes) |
| `internal/ppp` | Drives the system `pppd` via a PTY (Linux, or macOS with `--use-pppd`); otherwise runs a userspace PPP engine over `utun` (macOS) or `wintun` (Windows) |
| `internal/ppp/pppproto` | Minimal PPP LCP/IPCP negotiation (RFC 1661/1332), used by the macOS/Windows engine in place of pppd |
| `internal/hdlc` | HDLC framing/deframing between the relay loop and the local PPP transport (`pppd` PTY, or the userspace engine's pipe on macOS/Windows) |
| `internal/io` | Packet framing on the wire and the bidirectional relay loop |
| `internal/ipv4` | Per-OS routing table and DNS management (Linux/macOS/Windows) |
| `internal/userinput` | Interactive password/OTP prompts, with optional `pinentry` support |
| `pkg/version` | Build-time version string, injected via `-ldflags` |

## Known limitations

- **Windows support is new and needs real-world testing.** Since there's no `pppd` on Windows, `openfortivpn-go` implements its own minimal PPP client (LCP/IPCP negotiation, see `internal/ppp/pppproto`) on top of a [`wintun`](https://www.wintun.net/) virtual adapter. It requires **Administrator privileges**; `wintun.dll` is fetched automatically on first run if not already present (see [Requirements](#requirements)), which needs internet access at that point. If you hit issues, please open one with `-vvv --log-file` output attached.
- On macOS, every DNS query goes to the VPN nameservers while connected (as with FortiClient when the gateway defines no split-DNS domains), so name resolution depends on the tunnel being up.
- The macOS `utun` backend is new. `--pppd-ifname` doesn't apply to it, because the kernel picks the `utunN` name. If you hit issues, `--use-pppd` falls back to the previous behavior; please open an issue with `-vvv --log-file` output.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, the commit message convention this project relies on for automated release notes, and pull request expectations.

## License

Licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE), matching the license of the original project this is forked from.

## Acknowledgements

- [adrienverge/openfortivpn](https://github.com/adrienverge/openfortivpn) — the original C implementation this project is a Go rewrite of, including all of the FortiGate protocol reverse-engineering it's built on.
- Everyone who has contributed to the original project over the years.
