package signal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"time"
)

const (
	stunHeaderSize          = 20
	stunMagicCookie  uint32 = 0x2112A442
	stunBindingReq   uint16 = 0x0001
	stunBindingResp  uint16 = 0x0101
	attrMappedAddr   uint16 = 0x0001
	attrXorMapped    uint16 = 0x0020
	stunFamilyIPv4   byte   = 0x01
	stunFamilyIPv6   byte   = 0x02
	stunPerServerTTL        = 3 * time.Second
)

// QuerySTUN sends a minimal RFC 5389 Binding Request over UDP and parses the
// reflexive public IP:Port returned in XOR-MAPPED-ADDRESS or MAPPED-ADDRESS.
func QuerySTUN(ctx context.Context, serverAddr string) (*net.UDPAddr, error) {
	raddr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve stun server %s: %w", serverAddr, err)
	}

	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return nil, fmt.Errorf("dial stun server %s: %w", serverAddr, err)
	}
	defer conn.Close()

	req, txID, err := buildBindingRequest()
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(stunPerServerTTL)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("write stun request to %s: %w", serverAddr, err)
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("read stun response from %s: %w", serverAddr, err)
	}
	return parseBindingResponse(buf[:n], txID)
}

// DiscoverPublicIPv4 queries STUN servers in order until one succeeds.
func DiscoverPublicIPv4(ctx context.Context, servers []string) (*net.UDPAddr, string, error) {
	var lastErr error
	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		addr, err := QuerySTUN(ctx, srv)
		if err == nil {
			return addr, srv, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no STUN servers configured")
	}
	return nil, "", lastErr
}

// LocalGlobalIPv6 enumerates non-loopback, non-link-local, non-ULA global unicast IPv6 addresses.
func LocalGlobalIPv6() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip == nil || ip.To4() != nil {
				continue
			}
			if !ip.IsGlobalUnicast() || ip.IsPrivate() {
				continue
			}
			s := ip.String()
			if _, dup := seen[s]; !dup {
				seen[s] = struct{}{}
				out = append(out, s)
			}
		}
	}
	sort.Strings(out)
	return out
}

// DiscoverEndpoint collects the host's public IPv4 (via STUN) and global IPv6 addresses.
func DiscoverEndpoint(ctx context.Context, role string, listenPort int, stunServers []string) (*PeerEndpoint, string, error) {
	ipv6 := LocalGlobalIPv6()
	mapped, stunSrv, err := DiscoverPublicIPv4(ctx, stunServers)
	if err != nil && len(ipv6) == 0 {
		return nil, "", fmt.Errorf("discover endpoint failed (no IPv6 and STUN failed): %w", err)
	}

	ep := &PeerEndpoint{
		Role:      role,
		Port:      listenPort,
		IPv6:      ipv6,
		UpdatedAt: time.Now().UTC(),
	}
	if mapped != nil {
		ep.IPv4 = mapped.IP.String()
		if ep.Port == 0 {
			ep.Port = mapped.Port
		}
	}
	return ep, stunSrv, nil
}

func buildBindingRequest() ([]byte, [12]byte, error) {
	var txID [12]byte
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, txID, err
	}
	pkt := make([]byte, stunHeaderSize)
	binary.BigEndian.PutUint16(pkt[0:2], stunBindingReq)
	binary.BigEndian.PutUint16(pkt[2:4], 0)
	binary.BigEndian.PutUint32(pkt[4:8], stunMagicCookie)
	copy(pkt[8:20], txID[:])
	return pkt, txID, nil
}

func parseBindingResponse(pkt []byte, expectedTxID [12]byte) (*net.UDPAddr, error) {
	if len(pkt) < stunHeaderSize {
		return nil, fmt.Errorf("stun response too short: %d bytes", len(pkt))
	}
	msgType := binary.BigEndian.Uint16(pkt[0:2])
	msgLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if msgType != stunBindingResp {
		return nil, fmt.Errorf("unexpected stun message type: 0x%04x", msgType)
	}
	if cookie != stunMagicCookie {
		return nil, fmt.Errorf("invalid stun magic cookie: 0x%08x", cookie)
	}
	if !bytes.Equal(pkt[8:20], expectedTxID[:]) {
		return nil, errors.New("stun transaction ID mismatch")
	}
	if stunHeaderSize+msgLen > len(pkt) {
		return nil, fmt.Errorf("truncated stun message: header says %d, got %d", msgLen, len(pkt)-stunHeaderSize)
	}

	attrs := pkt[stunHeaderSize : stunHeaderSize+msgLen]
	var fallbackMapped *net.UDPAddr

	for len(attrs) >= 4 {
		attrType := binary.BigEndian.Uint16(attrs[0:2])
		attrLen := int(binary.BigEndian.Uint16(attrs[2:4]))
		attrs = attrs[4:]
		if attrLen > len(attrs) {
			return nil, errors.New("truncated stun attribute")
		}
		val := attrs[:attrLen]
		padded := (attrLen + 3) &^ 3
		if padded > len(attrs) {
			padded = len(attrs)
		}
		attrs = attrs[padded:]

		switch attrType {
		case attrXorMapped:
			addr, err := decodeMappedAttr(val, true, expectedTxID)
			if err == nil {
				return addr, nil
			}
		case attrMappedAddr:
			if addr, err := decodeMappedAttr(val, false, expectedTxID); err == nil {
				fallbackMapped = addr
			}
		}
	}

	if fallbackMapped != nil {
		return fallbackMapped, nil
	}
	return nil, errors.New("no XOR-MAPPED-ADDRESS or MAPPED-ADDRESS in stun response")
}

func decodeMappedAttr(val []byte, xor bool, txID [12]byte) (*net.UDPAddr, error) {
	if len(val) < 4 {
		return nil, errors.New("mapped address attribute too short")
	}
	family := val[1]
	port := binary.BigEndian.Uint16(val[2:4])
	if xor {
		port ^= uint16(stunMagicCookie >> 16)
	}

	switch family {
	case stunFamilyIPv4:
		if len(val) < 8 {
			return nil, errors.New("IPv4 mapped address too short")
		}
		ip := make(net.IP, 4)
		copy(ip, val[4:8])
		if xor {
			var cookieBytes [4]byte
			binary.BigEndian.PutUint32(cookieBytes[:], stunMagicCookie)
			for i := range 4 {
				ip[i] ^= cookieBytes[i]
			}
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil

	case stunFamilyIPv6:
		if len(val) < 20 {
			return nil, errors.New("IPv6 mapped address too short")
		}
		ip := make(net.IP, 16)
		copy(ip, val[4:20])
		if xor {
			var mask [16]byte
			binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
			copy(mask[4:16], txID[:])
			for i := range 16 {
				ip[i] ^= mask[i]
			}
		}
		return &net.UDPAddr{IP: ip, Port: int(port)}, nil

	default:
		return nil, fmt.Errorf("unsupported stun address family: 0x%02x", family)
	}
}
