package transport

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestPortHopperMakeBeforeBreak(t *testing.T) {
	srvTLS, _, err := BuildServerTLSConfig(ServerTLSOptions{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := Listen("127.0.0.1:0", srvTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Server echoes both Streams and RFC 9221 Datagrams.
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		defer conn.CloseWithError(0, "done")
		go func() {
			for {
				s, err := conn.AcceptStream(ctx)
				if err != nil {
					return
				}
				go func() {
					defer s.Close()
					_, _ = io.Copy(s, s)
				}()
			}
		}()
		for {
			pkt, err := conn.ReceiveDatagram(ctx)
			if err != nil {
				return
			}
			_ = conn.SendDatagram(pkt)
		}
	}()

	cliTLS := BuildClientTLSConfig(ClientTLSOptions{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	dc, err := DialWithTransport(ctx, ln.Addr().String(), cliTLS, DefaultQUICConfig())
	if err != nil {
		t.Fatalf("DialWithTransport failed: %v", err)
	}
	hopper := NewPortHopper(dc, 0)
	defer func() {
		_ = dc.Conn.CloseWithError(0, "test done")
		hopper.Close()
	}()

	verifyTraffic := func(label string) {
		t.Helper()
		// 1. Stream echo
		s, err := dc.Conn.OpenStreamSync(ctx)
		if err != nil {
			t.Fatalf("%s open stream: %v", label, err)
		}
		msg := []byte("hello-stream-" + label)
		if _, err := s.Write(msg); err != nil {
			t.Fatalf("%s write stream: %v", label, err)
		}
		_ = s.Close()
		got, err := io.ReadAll(s)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%s stream echo mismatch: got=%q err=%v", label, got, err)
		}

		// 2. Datagram echo
		dmsg := []byte("hello-datagram-" + label)
		if err := dc.Conn.SendDatagram(dmsg); err != nil {
			t.Fatalf("%s send datagram: %v", label, err)
		}
		dgot, err := dc.Conn.ReceiveDatagram(ctx)
		if err != nil || !bytes.Equal(dgot, dmsg) {
			t.Fatalf("%s datagram echo mismatch: got=%q err=%v", label, dgot, err)
		}
	}

	beforeAddr := hopper.LocalAddr().String()
	verifyTraffic("before-hop")

	if err := hopper.HopOnce(ctx); err != nil {
		t.Fatalf("HopOnce failed: %v", err)
	}
	afterAddr := hopper.LocalAddr().String()
	if beforeAddr == afterAddr {
		t.Fatalf("expected local address to change after port hop, still %s", afterAddr)
	}
	t.Logf("migrated local port: %s -> %s", beforeAddr, afterAddr)

	verifyTraffic("after-hop")
}
