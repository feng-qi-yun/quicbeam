package signal

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// punchMagic is a 4-byte prefix starting with 0x00,0x00 which is guaranteed
// disjoint from both QUIC (RFC 9000: first byte 0x40..0xFF) and STUN (RFC 5389:
// bytes 4..7 == 0x2112A442).
var punchMagic = [4]byte{0x00, 0x00, 'Q', 'B'}

// DemuxPacketConn wraps a net.PacketConn so a single UDP socket can serve
// QUIC traffic, periodic RFC 5389 STUN probes, and NAT hole-punching bursts
// simultaneously without restarting the socket (RFC 7983 first-byte demux).
type DemuxPacketConn struct {
	raw net.PacketConn

	mu          sync.Mutex
	stunWaiters map[[12]byte]chan []byte
	punchCount  atomic.Uint64
}

// NewDemuxPacketConn wraps raw for QUIC + STUN + Punch multiplexing.
func NewDemuxPacketConn(raw net.PacketConn) *DemuxPacketConn {
	return &DemuxPacketConn{
		raw:         raw,
		stunWaiters: make(map[[12]byte]chan []byte),
	}
}

// PunchReceivedCount returns the total number of NAT punch packets intercepted.
func (d *DemuxPacketConn) PunchReceivedCount() uint64 {
	return d.punchCount.Load()
}

// ReadFrom implements net.PacketConn. Non-QUIC STUN and punch packets are
// intercepted and dispatched internally; QUIC packets are returned with zero copy.
func (d *DemuxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := d.raw.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}
		if isSTUNPacket(p[:n]) {
			d.dispatchSTUN(p[:n])
			continue
		}
		if isPunchPacket(p[:n]) {
			d.punchCount.Add(1)
			slog.Debug("received NAT punch packet", "from", addr.String())
			continue
		}
		return n, addr, nil
	}
}

func (d *DemuxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return d.raw.WriteTo(p, addr)
}

func (d *DemuxPacketConn) Close() error                       { return d.raw.Close() }
func (d *DemuxPacketConn) LocalAddr() net.Addr                { return d.raw.LocalAddr() }
func (d *DemuxPacketConn) SetDeadline(t time.Time) error      { return d.raw.SetDeadline(t) }
func (d *DemuxPacketConn) SetReadDeadline(t time.Time) error  { return d.raw.SetReadDeadline(t) }
func (d *DemuxPacketConn) SetWriteDeadline(t time.Time) error { return d.raw.SetWriteDeadline(t) }

func (d *DemuxPacketConn) dispatchSTUN(pkt []byte) {
	var txID [12]byte
	copy(txID[:], pkt[8:20])

	d.mu.Lock()
	ch, ok := d.stunWaiters[txID]
	if ok {
		delete(d.stunWaiters, txID)
	}
	d.mu.Unlock()

	if ok {
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		select {
		case ch <- cp:
		default:
		}
	}
}

// QuerySTUN sends a STUN Binding Request through this active DemuxPacketConn
// (while QUIC is actively reading from it) and returns the socket's exact
// NAT-mapped external IP:Port.
func (d *DemuxPacketConn) QuerySTUN(ctx context.Context, serverAddr string) (*net.UDPAddr, error) {
	raddr, err := net.ResolveUDPAddr("udp4", serverAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve stun server %s: %w", serverAddr, err)
	}

	req, txID, err := buildBindingRequest()
	if err != nil {
		return nil, err
	}

	ch := make(chan []byte, 1)
	d.mu.Lock()
	d.stunWaiters[txID] = ch
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.stunWaiters, txID)
		d.mu.Unlock()
	}()

	if _, err := d.raw.WriteTo(req, raddr); err != nil {
		return nil, fmt.Errorf("write stun request to %s: %w", serverAddr, err)
	}

	timer := time.NewTimer(stunPerServerTTL)
	defer timer.Stop()

	select {
	case resp := <-ch:
		return parseBindingResponse(resp, txID)
	case <-timer.C:
		return nil, fmt.Errorf("stun timeout waiting for %s", serverAddr)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// DiscoverPublicIPv4 queries STUN servers in order on this DemuxPacketConn.
func (d *DemuxPacketConn) DiscoverPublicIPv4(ctx context.Context, servers []string) (*net.UDPAddr, string, error) {
	var lastErr error
	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		addr, err := d.QuerySTUN(ctx, srv)
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

// QuerySTUNOnPacketConn probes STUN directly on an idle PacketConn (before
// quic.Transport starts reading from it) so the client learns the exact NAT
// external port mapped to its soon-to-be QUIC socket.
func QuerySTUNOnPacketConn(ctx context.Context, pc net.PacketConn, servers []string) (*net.UDPAddr, string, error) {
	var lastErr error
	buf := make([]byte, 1500)

	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
		raddr, err := net.ResolveUDPAddr("udp4", srv)
		if err != nil {
			lastErr = err
			continue
		}
		req, txID, err := buildBindingRequest()
		if err != nil {
			return nil, "", err
		}

		deadline := time.Now().Add(stunPerServerTTL)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		_ = pc.SetDeadline(deadline)

		if _, err := pc.WriteTo(req, raddr); err != nil {
			lastErr = err
			continue
		}

		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				lastErr = err
				break
			}
			if !isSTUNPacket(buf[:n]) {
				continue
			}
			mapped, err := parseBindingResponse(buf[:n], txID)
			if err == nil {
				_ = pc.SetDeadline(time.Time{})
				return mapped, srv, nil
			}
		}
	}
	_ = pc.SetDeadline(time.Time{})
	if lastErr == nil {
		lastErr = errors.New("no STUN servers configured")
	}
	return nil, "", lastErr
}

// SendPunchBurst transmits a small burst of NAT hole-punching packets from pc
// to targetAddr to open outbound Cone NAT mappings on both sides.
func SendPunchBurst(pc net.PacketConn, targetAddr string, count int) error {
	raddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return fmt.Errorf("resolve punch target %s: %w", targetAddr, err)
	}
	if count <= 0 {
		count = 3
	}
	pkt := make([]byte, 16)
	copy(pkt[0:4], punchMagic[:])

	for i := range count {
		if _, err := pc.WriteTo(pkt, raddr); err != nil {
			return err
		}
		if i+1 < count {
			time.Sleep(30 * time.Millisecond)
		}
	}
	return nil
}

func isSTUNPacket(pkt []byte) bool {
	return len(pkt) >= stunHeaderSize &&
		(pkt[0]&0xC0) == 0 &&
		binary.BigEndian.Uint32(pkt[4:8]) == stunMagicCookie
}

func isPunchPacket(pkt []byte) bool {
	return len(pkt) >= 4 &&
		pkt[0] == punchMagic[0] &&
		pkt[1] == punchMagic[1] &&
		pkt[2] == punchMagic[2] &&
		pkt[3] == punchMagic[3]
}
