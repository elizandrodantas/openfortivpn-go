package io

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// tlsPipe returns two ends of an in-memory, real TLS connection (self-signed,
// over net.Pipe()), so RunLoop can be tested against a genuine *tls.Conn
// without a real network.
func tlsPipe(t *testing.T) (client, server *tls.Conn) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	c, s := net.Pipe()
	client = tls.Client(c, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	server = tls.Server(s, &tls.Config{Certificates: []tls.Certificate{cert}})

	done := make(chan error, 1)
	go func() { done <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return client, server
}

// TestRunLoop_UnblocksTLSReadWhenPTYErrors is a regression test for a real
// hang: when one goroutine (ptyReader) reports an error via errCh, the old
// code closed a "stopped" signal channel *before* cancelling the context —
// so the separate watcher goroutine responsible for force-unblocking a
// stuck sslReader (via an expired TLS deadline) almost always saw the
// "stopped" signal first and exited without ever unblocking anything.
// sslReader would then stay blocked on the TLS socket until the remote
// gateway's own idle-timeout (which can be minutes) closed the connection
// for us. This must now be prompt regardless of which goroutine errors.
func TestRunLoop_UnblocksTLSReadWhenPTYErrors(t *testing.T) {
	clientTLS, serverTLS := tlsPipe(t)
	defer clientTLS.Close()
	defer serverTLS.Close()

	ptyOurs, ptyTheirs := net.Pipe()
	defer ptyTheirs.Close()

	var onCancelCalled atomic.Bool
	cfg := &LoopConfig{
		TLSConn: clientTLS,
		PTY:     ptyOurs,
		OnCancel: func() {
			onCancelCalled.Store(true)
			ptyOurs.Close() // mimics proc.Close() causing ptyReader's Read to unblock
		},
	}

	// The gateway (serverTLS) never sends anything — sslReader blocks on
	// ReadPacket(cfg.TLSConn) for the entire test, exactly like a real
	// gateway that isn't responding.
	_ = serverTLS

	runErrCh := make(chan error, 1)
	go func() { runErrCh <- RunLoop(context.Background(), cfg) }()

	// Simulate the PPP engine failing (e.g. our LCP/IPCP negotiation timing
	// out) by closing its end of the PTY pipe — this is what
	// engineSide.Close() does in the real Windows engine.
	time.Sleep(50 * time.Millisecond)
	closedAt := time.Now()
	ptyTheirs.Close()

	select {
	case err := <-runErrCh:
		elapsed := time.Since(closedAt)
		t.Logf("RunLoop returned %v after PTY close", elapsed)
		if err == nil {
			t.Fatal("expected RunLoop to return an error (ptyReader EOF), got nil")
		}
		if elapsed > time.Second {
			t.Errorf("RunLoop took %v to return — should be near-instant, not left waiting on something", elapsed)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunLoop did not return within 3s — sslReader was left blocked on the TLS socket instead of being force-unblocked")
	}

	if !onCancelCalled.Load() {
		t.Error("OnCancel was never called — the other goroutines were never told to unblock")
	}
}
