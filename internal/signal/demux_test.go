package signal

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func startMockSTUNResponder(t *testing.T, mappedIP net.IP, mappedPort int) string {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	go func() {
		buf := make([]byte, 512)
		for {
			n, raddr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n < stunHeaderSize {
				continue
			}
			resp := make([]byte, stunHeaderSize+12)
			binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
			binary.BigEndian.PutUint16(resp[2:4], 12)
			binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
			copy(resp[8:20], buf[8:20])

			binary.BigEndian.PutUint16(resp[20:22], attrXorMapped)
			binary.BigEndian.PutUint16(resp[22:24], 8)
			resp[24] = 0
			resp[25] = stunFamilyIPv4
			binary.BigEndian.PutUint16(resp[26:28], uint16(mappedPort)^uint16(stunMagicCookie>>16))
			var cookieBytes [4]byte
			binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
			ip4 := mappedIP.To4()
			for i := range 4 {
				resp[28+i] = ip4[i] ^ cookieBytes[i]
			}
			_, _ = pc.WriteToUDP(resp, raddr)
		}
	}()
	return pc.LocalAddr().String()
}

func TestDemuxPacketConnSeparatesQUICSTUNAndPunch(t *testing.T) {
	raw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	demux := NewDemuxPacketConn(raw)
	defer demux.Close()

	stunAddr := startMockSTUNResponder(t, net.IPv4(198, 51, 100, 77), 44321)

	// Simulate QUIC transport reader goroutine continuously calling demux.ReadFrom.
	quicRx := make(chan []byte, 4)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, _, err := demux.ReadFrom(buf)
			if err != nil {
				return
			}
			cp := make([]byte, n)
			copy(cp, buf[:n])
			quicRx <- cp
		}
	}()

	// 1. Run STUN through DemuxPacketConn while ReadFrom is actively pumping.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	mapped, err := demux.QuerySTUN(ctx, stunAddr)
	if err != nil {
		t.Fatalf("DemuxPacketConn.QuerySTUN failed: %v", err)
	}
	if mapped.IP.String() != "198.51.100.77" || mapped.Port != 44321 {
		t.Fatalf("unexpected STUN mapped addr: %s", mapped.String())
	}

	// 2. Send punch burst + simulated QUIC short-header packet (0x40...) from a peer socket.
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()

	if err := SendPunchBurst(peer, demux.LocalAddr().String(), 2); err != nil {
		t.Fatalf("SendPunchBurst failed: %v", err)
	}
	quicPkt := []byte{0x40, 0x01, 0x02, 0x03, 0x04}
	if _, err := peer.WriteTo(quicPkt, demux.LocalAddr()); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-quicRx:
		if len(got) != len(quicPkt) || got[0] != 0x40 {
			t.Fatalf("unexpected QUIC packet: %x", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for QUIC packet through DemuxPacketConn")
	}

	if demux.PunchReceivedCount() < 2 {
		t.Fatalf("expected >= 2 punch packets intercepted, got %d", demux.PunchReceivedCount())
	}
}

func TestQuerySTUNOnIdlePacketConn(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	stunAddr := startMockSTUNResponder(t, net.IPv4(203, 0, 113, 88), 55112)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	mapped, srv, err := QuerySTUNOnPacketConn(ctx, pc, []string{stunAddr})
	if err != nil {
		t.Fatalf("QuerySTUNOnPacketConn failed: %v", err)
	}
	if srv != stunAddr || mapped.IP.String() != "203.0.113.88" || mapped.Port != 55112 {
		t.Fatalf("unexpected result: mapped=%s srv=%s", mapped, srv)
	}
}
