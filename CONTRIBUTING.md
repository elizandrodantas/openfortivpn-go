# Contributing to openfortivpn-go

Thanks for taking the time to contribute! This document covers how to get set up, the commit message convention this project relies on, and what's expected of a pull request.

## Development setup

Requires Go (see `go.mod` for the minimum version) and `make`.

```sh
git clone https://github.com/elizandrodantas/openfortivpn-go.git
cd openfortivpn-go
make build   # build the binary for your current OS/architecture
make test    # go test -race ./...
make lint    # go vet + staticcheck
```

Run `make help` to see all available targets.

Before opening a pull request, please make sure both `make test` and `make lint` pass locally. CI runs these on every push/PR (see `.github/workflows/`), but catching issues locally first saves everyone a review round-trip.

## Commit message convention (required)

This project uses **[Conventional Commits](https://www.conventionalcommits.org/)**, and it's not just a style preference: the `release.yml` workflow **parses commit subjects** to build the changelog attached to every GitHub Release automatically, grouped by type. Commits that don't follow the convention still get released, but they land in an "Other Changes" bucket instead of their proper section — so please follow the format.

Format: `<type>: <short description>` (optionally `<type>(<scope>): <short description>`)

Recognized types, and the order they're rendered in release notes:

1. `feat` — a new feature
2. `chore` — maintenance work with no user-facing behavior change (deps, tooling, refactors)
3. `fix` — a bug fix
4. `build`, `ci`, `docs`, `perf`, `refactor`, `revert`, `style`, `test` — other conventional types, included in the changelog under their own headings

Examples from this repo's own history:

```
feat: add --log-file flag for full debug logging to file
fix: macOS DNS via /etc/resolver/ (not networksetup) — avoids interface binding
chore: remove all log truncation — print full bodies and XML
```

Keep the description short (it's the changelog line), and use the commit body for any additional detail that doesn't belong in the summary.

## Pull requests

- Keep PRs focused — one logical change per PR is easier to review and produces a cleaner changelog entry.
- Update the [README](README.md) if you're adding or changing user-facing behavior (a new flag, config key, or platform-specific behavior).
- If you're touching platform-specific code (`internal/ipv4/*_darwin.go`, `*_windows.go`, `*_unix.go`, `internal/ppp/*`), please describe in the PR how you tested it — CI only runs on Linux/macOS runners, so Windows changes in particular may need manual verification.
- Windows tunnel support (the PPP/IPCP/TUN data-plane) is currently unimplemented — see the README's [Known limitations](README.md#known-limitations) section. This is one of the most impactful areas to contribute to if you're looking for something substantial to work on.
