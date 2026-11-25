package signal

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/feng-qi-yun/quicbeam/internal/config"
)

func TestSTUNMockServer(t *testing.T) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Minimal mock RFC 5389 STUN responder returning XOR-MAPPED-ADDRESS 203.0.113.42:54321.
	go func() {
		buf := make([]byte, 512)
		n, raddr, err := pc.ReadFromUDP(buf)
		if err != nil || n < stunHeaderSize {
			return
		}
		resp := make([]byte, stunHeaderSize+12)
		binary.BigEndian.PutUint16(resp[0:2], stunBindingResp)
		binary.BigEndian.PutUint16(resp[2:4], 12)
		binary.BigEndian.PutUint32(resp[4:8], stunMagicCookie)
		copy(resp[8:20], buf[8:20]) // echo txID

		// XOR-MAPPED-ADDRESS attribute (type 0x0020, len 8)
		binary.BigEndian.PutUint16(resp[20:22], attrXorMapped)
		binary.BigEndian.PutUint16(resp[22:24], 8)
		resp[24] = 0
		resp[25] = stunFamilyIPv4
		binary.BigEndian.PutUint16(resp[26:28], uint16(54321)^uint16(stunMagicCookie>>16))
		var cookieBytes [4]byte
		binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
		ip := net.IPv4(203, 0, 113, 42).To4()
		for i := range 4 {
			resp[28+i] = ip[i] ^ cookieBytes[i]
		}
		_, _ = pc.WriteToUDP(resp, raddr)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	got, err := QuerySTUN(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("QuerySTUN failed: %v", err)
	}
	if got.IP.String() != "203.0.113.42" || got.Port != 54321 {
		t.Fatalf("unexpected STUN mapped addr: got %s, want 203.0.113.42:54321", got.String())
	}
}

func TestSignalEncryptDecryptAndHTTPExchange(t *testing.T) {
	var mu sync.Mutex
	store := make(map[string]string)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			store[r.URL.Path] = string(b)
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			v, ok := store[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(v))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer srv.Close()

	cfg := &config.SignalConfig{
		URL:   srv.URL,
		Room:  "my-room",
		Token: "test-token",
	}
	client := NewClient(cfg, "super-secret-psk")

	want := &PeerEndpoint{
		Role:      config.RoleServer,
		IPv4:      "198.51.100.9",
		Port:      443,
		IPv6:      []string{"2001:db8::1"},
		UpdatedAt: time.Now().UTC().Truncate(time.Second),
	}

	ctx := context.Background()
	if err := client.Publish(ctx, want); err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// Ensure wrong PSK cannot decrypt stored value.
	wrongClient := NewClient(cfg, "wrong-psk")
	if _, err := wrongClient.FetchPeer(ctx, config.RoleServer); err == nil {
		t.Fatalf("expected decryption error with wrong PSK")
	}

	got, err := client.FetchPeer(ctx, config.RoleServer)
	if err != nil {
		t.Fatalf("FetchPeer failed: %v", err)
	}
	if got.IPv4 != want.IPv4 || got.Port != want.Port || len(got.IPv6) != 1 || got.IPv6[0] != "2001:db8::1" {
		t.Fatalf("endpoint mismatch: got %+v, want %+v", got, want)
	}

	v6First := got.CandidateAddrs(true)
	if len(v6First) != 2 || v6First[0] != "[2001:db8::1]:443" || v6First[1] != "198.51.100.9:443" {
		t.Fatalf("unexpected v6-first candidates: %v", v6First)
	}
	v4First := got.CandidateAddrs(false)
	if len(v4First) != 2 || v4First[0] != "198.51.100.9:443" || v4First[1] != "[2001:db8::1]:443" {
		t.Fatalf("unexpected v4-first candidates: %v", v4First)
	}
}
