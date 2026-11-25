package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	migrationProbeTimeout = 5 * time.Second
	oldPathDrainDelay     = 2 * time.Second
	maxTransportPoolSize  = 32
)

type transportSlot struct {
	tr *quic.Transport
	pc net.PacketConn
}

func (s transportSlot) localAddr() string {
	if s.pc != nil {
		return s.pc.LocalAddr().String()
	}
	return ""
}

func (s transportSlot) close() {
	if s.tr != nil {
		_ = s.tr.Close()
	}
	if s.pc != nil {
		_ = s.pc.Close()
	}
}

// PortHopper performs Make-Before-Break QUIC Connection Migration (RFC 9000)
// by periodically probing a fresh local UDP source port and switching active
// traffic without interrupting streams or RFC 9221 datagrams.
//
// In quic-go, every *quic.Transport ever used by a *quic.Conn remains registered
// in the connection's connIDGenerator until the connection itself closes; calling
// Transport.Close() or closing its underlying PacketConn earlier abruptly destroys
// the live QUIC connection without sending CONNECTION_CLOSE. PortHopper therefore
// keeps retired transports alive in a bounded FIFO pool and only closes them when
// PortHopper.Close() is called after connection teardown.
type PortHopper struct {
	conn        *quic.Conn
	network     string
	remoteAddr  string
	interval    time.Duration
	drainDelay  time.Duration
	maxPoolSize int

	mu          sync.Mutex
	currentSlot transportSlot
	currentPath *quic.Path
	retired     []transportSlot
	closed      bool
}

// NewPortHopper creates a PortHopper managing the transports of a DialedConn.
func NewPortHopper(dc *DialedConn, interval time.Duration) *PortHopper {
	return &PortHopper{
		conn:        dc.Conn,
		network:     dc.Network,
		remoteAddr:  dc.Conn.RemoteAddr().String(),
		interval:    interval,
		drainDelay:  oldPathDrainDelay,
		maxPoolSize: maxTransportPoolSize,
		currentSlot: transportSlot{
			tr: dc.Transport,
			pc: dc.PacketConn,
		},
	}
}

// LocalAddr returns the currently active local UDP address.
func (h *PortHopper) LocalAddr() net.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.currentSlot.pc != nil {
		return h.currentSlot.pc.LocalAddr()
	}
	return h.conn.LocalAddr()
}

// Run periodically hops to a new local UDP source port until ctx or the QUIC
// connection is closed.
func (h *PortHopper) Run(ctx context.Context) {
	if h.interval <= 0 {
		return
	}
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-h.conn.Context().Done():
			return
		case <-ticker.C:
			if err := h.HopOnce(ctx); err != nil {
				if ctx.Err() != nil || h.conn.Context().Err() != nil {
					return
				}
				slog.Warn("QUIC port hop failed, keeping current path", "err", err)
			}
		}
	}
}

// HopOnce binds a new ephemeral local UDP port (or reuses the oldest retired
// transport once the bounded pool is full), probes it with PATH_CHALLENGE,
// and atomically switches the QUIC connection onto the new path.
func (h *PortHopper) HopOnce(ctx context.Context) error {
	slot, reused, err := h.acquireSlot()
	if err != nil {
		return err
	}

	path, err := h.conn.AddPath(slot.tr)
	if err != nil {
		if reused {
			h.parkRetired(slot)
		} else {
			slot.close()
		}
		return fmt.Errorf("add QUIC path: %w", err)
	}

	probeStart := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, migrationProbeTimeout)
	err = path.Probe(probeCtx)
	cancel()
	if err != nil {
		_ = path.Close()
		// Probe may have registered slot.tr on h.conn; never close it while h.conn is alive.
		h.parkRetired(slot)
		return fmt.Errorf("probe new path %s: %w", slot.localAddr(), err)
	}
	probeMs := time.Since(probeStart).Milliseconds()

	if err := path.Switch(); err != nil {
		_ = path.Close()
		h.parkRetired(slot)
		return fmt.Errorf("switch to path %s: %w", slot.localAddr(), err)
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		slot.close()
		return fmt.Errorf("port hopper already closed")
	}
	prevSlot := h.currentSlot
	prevPath := h.currentPath
	oldAddr := prevSlot.localAddr()
	h.currentSlot = slot
	h.currentPath = path
	if prevSlot.tr != nil || prevSlot.pc != nil {
		h.retired = append(h.retired, prevSlot)
	}
	poolSize := len(h.retired) + 1
	h.mu.Unlock()

	slog.Info("QUIC connection migrated (port hop)",
		"old_local", oldAddr,
		"new_local", slot.localAddr(),
		"remote", h.remoteAddr,
		"probe_ms", probeMs,
		"reused_socket", reused,
		"pool_size", poolSize,
	)

	// Retire the previous quic.Path after a brief drain window so the peer can
	// issue fresh Connection IDs, without closing the underlying quic.Transport.
	if prevPath != nil {
		go func(oldPath *quic.Path, delay time.Duration) {
			if delay > 0 {
				t := time.NewTimer(delay)
				defer t.Stop()
				select {
				case <-t.C:
				case <-h.conn.Context().Done():
					return
				}
			}
			_ = oldPath.Close()
		}(prevPath, h.drainDelay)
	}
	return nil
}

func (h *PortHopper) acquireSlot() (transportSlot, bool, error) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return transportSlot{}, false, fmt.Errorf("port hopper already closed")
	}
	if h.maxPoolSize > 0 && len(h.retired)+1 >= h.maxPoolSize && len(h.retired) > 0 {
		slot := h.retired[0]
		h.retired = h.retired[1:]
		h.mu.Unlock()
		return slot, true, nil
	}
	h.mu.Unlock()

	pc, err := net.ListenUDP(h.network, &net.UDPAddr{Port: 0})
	if err != nil {
		return transportSlot{}, false, fmt.Errorf("bind new %s socket: %w", h.network, err)
	}
	return transportSlot{
		tr: &quic.Transport{Conn: pc},
		pc: pc,
	}, false, nil
}

func (h *PortHopper) parkRetired(slot transportSlot) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		slot.close()
		return
	}
	h.retired = append(h.retired, slot)
	h.mu.Unlock()
}

// Close tears down all transports and UDP sockets managed by this PortHopper.
// Callers must ensure the QUIC connection is closed or no longer needed first.
func (h *PortHopper) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	slots := make([]transportSlot, 0, len(h.retired)+1)
	if h.currentSlot.tr != nil || h.currentSlot.pc != nil {
		slots = append(slots, h.currentSlot)
	}
	slots = append(slots, h.retired...)
	h.currentSlot = transportSlot{}
	h.currentPath = nil
	h.retired = nil
	h.mu.Unlock()

	for _, slot := range slots {
		slot.close()
	}
}
