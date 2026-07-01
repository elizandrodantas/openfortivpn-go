//go:build windows

// Package wintundll makes the Wintun driver DLL (https://www.wintun.net/,
// the same driver WireGuard/Tailscale use) available before any Wintun API
// call is made. golang.zx2c4.com/wintun loads a bare "wintun.dll" via the
// standard Windows DLL search order, which checks the application directory
// first, so this package only needs to make sure a valid copy sits there
// (or, failing that, in a directory explicitly added to the search path).
//
// If wintun.dll is already present next to the executable or in System32,
// it's used as-is (whatever version is already installed — from a previous
// run of this tool, or another Wintun-based application). Only if it's
// missing does this package fetch it directly from wintun.net for the
// running architecture, verifying its SHA-256 against a pinned digest
// before ever loading it, so a compromised or tampered download is refused
// rather than silently executed.
package wintundll

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

// wintunVersion pins the exact wintun.net release fetched, so a download is
// always checked against a known-good digest rather than trusting whatever
// the server happens to return.
const wintunVersion = "0.14.1"

var wintunZipURL = fmt.Sprintf("https://www.wintun.net/builds/wintun-%s.zip", wintunVersion)

// wintunSHA256 maps GOARCH to the expected SHA-256 digest of
// wintun/bin/<arch>/wintun.dll inside that release's zip.
var wintunSHA256 = map[string]string{
	"amd64": "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce",
	"arm64": "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80",
}

const downloadTimeout = 30 * time.Second

// Ensure makes wintun.dll discoverable via the standard Windows DLL search
// order before any Wintun API call is made.
func Ensure() error {
	digest, ok := wintunSHA256[runtime.GOARCH]
	if !ok {
		return fmt.Errorf("wintundll: unsupported architecture %s", runtime.GOARCH)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("wintundll: locate executable: %w", err)
	}
	primary := filepath.Join(filepath.Dir(exe), "wintun.dll")

	if fileMatchesDigest(primary, digest) {
		return nil // already present next to the executable
	}
	if fileMatchesDigest(filepath.Join(os.Getenv("WINDIR"), "System32", "wintun.dll"), digest) {
		return nil // already installed system-wide (e.g. by another Wintun app)
	}

	data, err := downloadAndVerify(runtime.GOARCH, digest)
	if err != nil {
		return fmt.Errorf("wintundll: %w", err)
	}

	if err := os.WriteFile(primary, data, 0o644); err == nil {
		return nil
	}

	// Executable directory not writable — fall back to a per-user cache
	// directory and tell Windows to look there too.
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return fmt.Errorf("wintundll: locate cache dir: %w", err)
	}
	dir := filepath.Join(cacheDir, "openfortivpn-go")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("wintundll: create %s: %w", dir, err)
	}
	fallback := filepath.Join(dir, "wintun.dll")
	if !fileMatchesDigest(fallback, digest) {
		if err := os.WriteFile(fallback, data, 0o644); err != nil {
			return fmt.Errorf("wintundll: write %s: %w", fallback, err)
		}
	}
	if err := windows.SetDllDirectory(dir); err != nil {
		return fmt.Errorf("wintundll: SetDllDirectory(%s): %w", dir, err)
	}
	return nil
}

// downloadAndVerify fetches the wintun.net release zip and extracts+verifies
// the DLL for the given architecture.
func downloadAndVerify(arch, wantDigest string) ([]byte, error) {
	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(wintunZipURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", wintunZipURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: unexpected status %d", wintunZipURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20)) // generous cap; real file is ~750 KiB
	if err != nil {
		return nil, fmt.Errorf("read download body: %w", err)
	}

	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, fmt.Errorf("open downloaded zip: %w", err)
	}
	entryName := fmt.Sprintf("wintun/bin/%s/wintun.dll", arch)
	f, err := zr.Open(entryName)
	if err != nil {
		return nil, fmt.Errorf("find %s in downloaded zip: %w", entryName, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("extract %s: %w", entryName, err)
	}

	got := sha256Hex(data)
	if got != wantDigest {
		return nil, fmt.Errorf("wintun.dll checksum mismatch for %s: got %s, want %s (refusing to use a download that doesn't match the pinned digest)", arch, got, wantDigest)
	}
	return data, nil
}

func fileMatchesDigest(path, digest string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return sha256Hex(data) == digest
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
