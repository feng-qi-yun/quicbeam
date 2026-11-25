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
)

// PortHopper performs Make-Before-Break QUIC Connection Migration (RFC 9000)
// by periodically probing a fresh local UDP source port and switching active
// traffic without interrupting streams or RFC 9221 datagrams.
type PortHopper struct {
	conn       *quic.Conn
	network    string
	remoteAddr string
	interval   time.Duration

	mu        sync.Mutex
	currentTr *quic.Transport
	currentPC *net.UDPConn
	closed    bool
}

// NewPortHopper creates a PortHopper managing the transports of a DialedConn.
func NewPortHopper(dc *DialedConn, interval time.Duration) *PortHopper {
	return &PortHopper{
		conn:       dc.Conn,
		network:    dc.Network,
		remoteAddr: dc.Conn.RemoteAddr().String(),
		interval:   interval,
		currentTr:  dc.Transport,
		currentPC:  dc.UDPConn,
	}
}

// LocalAddr returns the currently active local UDP address.
func (h *PortHopper) LocalAddr() net.Addr {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.currentPC != nil {
		return h.currentPC.LocalAddr()
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

// HopOnce binds a new ephemeral local UDP port, probes it with PATH_CHALLENGE,
// and atomically switches the QUIC connection onto the new path.
func (h *PortHopper) HopOnce(ctx context.Context) error {
	pc, err := net.ListenUDP(h.network, &net.UDPAddr{Port: 0})
	if err != nil {
		return fmt.Errorf("bind new %s socket: %w", h.network, err)
	}
	tr := &quic.Transport{Conn: pc}

	path, err := h.conn.AddPath(tr)
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return fmt.Errorf("add QUIC path: %w", err)
	}

	probeStart := time.Now()
	probeCtx, cancel := context.WithTimeout(ctx, migrationProbeTimeout)
	err = path.Probe(probeCtx)
	cancel()
	if err != nil {
		_ = path.Close()
		_ = tr.Close()
		_ = pc.Close()
		return fmt.Errorf("probe new path %s: %w", pc.LocalAddr().String(), err)
	}
	probeMs := time.Since(probeStart).Milliseconds()

	if err := path.Switch(); err != nil {
		_ = path.Close()
		_ = tr.Close()
		_ = pc.Close()
		return fmt.Errorf("switch to path %s: %w", pc.LocalAddr().String(), err)
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		_ = tr.Close()
		_ = pc.Close()
		return fmt.Errorf("port hopper already closed")
	}
	prevTr, prevPC := h.currentTr, h.currentPC
	oldAddr := ""
	if prevPC != nil {
		oldAddr = prevPC.LocalAddr().String()
	}
	h.currentTr = tr
	h.currentPC = pc
	h.mu.Unlock()

	slog.Info("QUIC connection migrated (port hop)",
		"old_local", oldAddr,
		"new_local", pc.LocalAddr().String(),
		"remote", h.remoteAddr,
		"probe_ms", probeMs,
	)

	// Drain in-flight packets on the previous path briefly before closing it.
	if prevTr != nil || prevPC != nil {
		go func(oldTr *quic.Transport, oldPC *net.UDPConn) {
			time.Sleep(oldPathDrainDelay)
			if oldTr != nil {
				_ = oldTr.Close()
			}
			if oldPC != nil {
				_ = oldPC.Close()
			}
		}(prevTr, prevPC)
	}
	return nil
}

// Close tears down the currently active transport and UDP socket.
func (h *PortHopper) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	tr, pc := h.currentTr, h.currentPC
	h.currentTr = nil
	h.currentPC = nil
	h.mu.Unlock()

	if tr != nil {
		_ = tr.Close()
	}
	if pc != nil {
		_ = pc.Close()
	}
}
