package transport

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGenerateCertFilesAndPinning(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	pin, err := GenerateCertFiles(certPath, keyPath, "www.cloudflare.com")
	if err != nil {
		t.Fatalf("GenerateCertFiles failed: %v", err)
	}
	if len(pin) != 64 {
		t.Fatalf("expected 64-char sha256 hex, got %q", pin)
	}

	srvTLS, ephemeral, err := BuildServerTLSConfig(ServerTLSOptions{
		CertFile:   certPath,
		KeyFile:    keyPath,
		ServerName: "www.cloudflare.com",
	})
	if err != nil {
		t.Fatalf("BuildServerTLSConfig failed: %v", err)
	}
	if ephemeral {
		t.Fatalf("expected non-ephemeral cert when loading from disk")
	}

	ln, err := Listen("127.0.0.1:0", srvTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		for {
			c, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			_ = c.CloseWithError(0, "ok")
		}
	}()

	// 1. Correct SHA-256 pin succeeds (even without InsecureSkipVerify).
	goodTLS := BuildClientTLSConfig(ClientTLSOptions{
		ServerName: "www.cloudflare.com",
		CertSHA256: pin,
	})
	conn, err := Dial(ctx, ln.Addr().String(), goodTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("expected pinned cert dial to succeed, got %v", err)
	}
	_ = conn.CloseWithError(0, "done")

	// 2. Wrong SHA-256 pin is rejected.
	badPin := strings.Repeat("0", 64)
	if badPin == pin {
		badPin = strings.Repeat("1", 64)
	}
	badTLS := BuildClientTLSConfig(ClientTLSOptions{
		ServerName: "www.cloudflare.com",
		CertSHA256: badPin,
	})
	if c, err := Dial(ctx, ln.Addr().String(), badTLS, DefaultQUICConfig()); err == nil {
		_ = c.CloseWithError(0, "unexpected")
		t.Fatalf("expected mismatched cert pin to fail handshake")
	}
}
