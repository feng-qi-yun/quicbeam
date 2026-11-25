package forward

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/feng-qi-yun/quicbeam/internal/config"
	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr().String()
}

func startUDPEcho(t *testing.T) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp resolve: %v", err)
	}
	pc, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], raddr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestHandshakePSKRejection(t *testing.T) {
	tlsCfg, _, err := transport.BuildServerTLSConfig(transport.ServerTLSOptions{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := transport.Listen("127.0.0.1:0", tlsCfg, transport.DefaultQUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mgr, err := NewManager(ctx, config.RoleServer, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer mgr.Close()

	go func() {
		_ = ServeListener(ctx, ln, "correct-psk", mgr)
	}()

	clientTLS := transport.BuildClientTLSConfig(transport.ClientTLSOptions{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	conn, err := transport.Dial(ctx, ln.Addr().String(), clientTLS, transport.DefaultQUICConfig())
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.CloseWithError(0, "done")

	if _, err := HandshakeClient(ctx, conn, "wrong-psk", nil); err == nil {
		t.Fatalf("expected handshake to fail with wrong PSK, got nil")
	}
}

func TestSymmetricForwardingTCPAndUDP(t *testing.T) {
	for _, tc := range []struct {
		name             string
		forwardsOnServer bool
	}{
		{name: "client-ingress (direct dial)", forwardsOnServer: false},
		{name: "server-ingress (reverse dial)", forwardsOnServer: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tcpEchoAddr := startTCPEcho(t)
			udpEchoAddr := startUDPEcho(t)

			forwards := []config.PortForward{
				{Name: "tcp-echo", Proto: config.ProtoTCP, Listen: "127.0.0.1:0", Target: tcpEchoAddr},
				{Name: "udp-echo", Proto: config.ProtoUDP, Listen: "127.0.0.1:0", Target: udpEchoAddr},
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			var serverForwards, clientForwards []config.PortForward
			if tc.forwardsOnServer {
				serverForwards = forwards
			} else {
				clientForwards = forwards
			}

			srvMgr, err := NewManager(ctx, config.RoleServer, serverForwards)
			if err != nil {
				t.Fatalf("server manager: %v", err)
			}
			defer srvMgr.Close()

			cliMgr, err := NewManager(ctx, config.RoleClient, clientForwards)
			if err != nil {
				t.Fatalf("client manager: %v", err)
			}
			defer cliMgr.Close()

			srvTLS, _, err := transport.BuildServerTLSConfig(transport.ServerTLSOptions{ServerName: "localhost"})
			if err != nil {
				t.Fatal(err)
			}
			ln, err := transport.Listen("127.0.0.1:0", srvTLS, transport.DefaultQUICConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			const psk = "phase1-test-secret"
			go func() {
				_ = ServeListener(ctx, ln, psk, srvMgr)
			}()

			cliTLS := transport.BuildClientTLSConfig(transport.ClientTLSOptions{
				ServerName:         "localhost",
				InsecureSkipVerify: true,
			})
			conn, err := transport.Dial(ctx, ln.Addr().String(), cliTLS, transport.DefaultQUICConfig())
			if err != nil {
				t.Fatalf("client dial: %v", err)
			}
			peerUDP, err := HandshakeClient(ctx, conn, psk, cliMgr.UDPChannels())
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}

			go func() {
				_ = cliMgr.AttachSession(conn, peerUDP)
			}()

			// Wait briefly for server AttachSession to complete.
			deadline := time.Now().Add(2 * time.Second)
			for srvMgr.activeSession() == nil || cliMgr.activeSession() == nil {
				if time.Now().After(deadline) {
					t.Fatal("timed out waiting for active tunnel sessions")
				}
				time.Sleep(10 * time.Millisecond)
			}

			ingressMgr := cliMgr
			if tc.forwardsOnServer {
				ingressMgr = srvMgr
			}

			// 1. Verify concurrent TCP forwarding over QUIC Streams.
			tcpListen := ingressMgr.ListenAddr("tcp-echo")
			var wg sync.WaitGroup
			for i := range 5 {
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					c, err := net.DialTimeout("tcp", tcpListen, 2*time.Second)
					if err != nil {
						t.Errorf("tcp dial %d: %v", idx, err)
						return
					}
					defer c.Close()
					msg := bytes.Repeat([]byte(fmt.Sprintf("stream-%d-", idx)), 256)
					if _, err := c.Write(msg); err != nil {
						t.Errorf("tcp write %d: %v", idx, err)
						return
					}
					got := make([]byte, len(msg))
					if _, err := io.ReadFull(c, got); err != nil {
						t.Errorf("tcp read %d: %v", idx, err)
						return
					}
					if !bytes.Equal(got, msg) {
						t.Errorf("tcp mismatch on stream %d", idx)
					}
				}(i)
			}
			wg.Wait()

			// 2. Verify UDP forwarding over RFC 9221 QUIC Datagrams.
			udpListen := ingressMgr.ListenAddr("udp-echo")
			uaddr, err := net.ResolveUDPAddr("udp", udpListen)
			if err != nil {
				t.Fatal(err)
			}
			uc, err := net.DialUDP("udp", nil, uaddr)
			if err != nil {
				t.Fatalf("udp dial: %v", err)
			}
			defer uc.Close()
			_ = uc.SetDeadline(time.Now().Add(3 * time.Second))

			buf := make([]byte, 4096)
			for i := range 50 {
				payload := bytes.Repeat([]byte(fmt.Sprintf("dgram-%02d-", i)), 100) // 900B
				if _, err := uc.Write(payload); err != nil {
					t.Fatalf("udp write %d: %v", i, err)
				}
				n, err := uc.Read(buf)
				if err != nil {
					t.Fatalf("udp read %d: %v", i, err)
				}
				if !bytes.Equal(buf[:n], payload) {
					t.Fatalf("udp mismatch on packet %d", i)
				}
			}

			// 3. Verify oversized 1408B Moonlight LAN video packets via unreliable fragmentation.
			for i := range 20 {
				payload := bytes.Repeat([]byte(fmt.Sprintf("vid-%02d--", i)), 176) // 1408B
				if _, err := uc.Write(payload); err != nil {
					t.Fatalf("oversized udp write %d: %v", i, err)
				}
				n, err := uc.Read(buf)
				if err != nil {
					t.Fatalf("oversized udp read %d: %v", i, err)
				}
				if !bytes.Equal(buf[:n], payload) {
					t.Fatalf("oversized udp mismatch on packet %d", i)
				}
			}
		})
	}
}
