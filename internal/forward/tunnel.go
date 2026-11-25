package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/feng-qi-yun/quicbeam/internal/config"
)

const (
	errCodeAuthFailed    quic.ApplicationErrorCode = 0x01
	errCodeSessionSwap   quic.ApplicationErrorCode = 0x02
	errCodeNormalClose   quic.ApplicationErrorCode = 0x00
	udpReadBufSize                                 = 65536
	tcpDialTimeout                                 = 5 * time.Second
	mtuWarnCooldown                                = 5 * time.Second
)

// udpIngress represents a local UDP listener whose traffic is sent over QUIC Datagrams
// with a 1-byte channel ID prefix.
type udpIngress struct {
	id     uint8
	spec   config.PortForward
	conn   *net.UDPConn
	mu     sync.RWMutex
	client *net.UDPAddr
}

func (u *udpIngress) setClient(addr *net.UDPAddr) {
	u.mu.Lock()
	u.client = addr
	u.mu.Unlock()
}

func (u *udpIngress) getClient() *net.UDPAddr {
	u.mu.RLock()
	addr := u.client
	u.mu.RUnlock()
	return addr
}

// udpEgress represents a remote UDP target socket managed by an active Session.
type udpEgress struct {
	id     uint8
	target string
	conn   *net.UDPConn
}

// Session represents a single authenticated QUIC connection carrying multiplexed
// TCP Streams and RFC 9221 Unreliable UDP Datagrams.
type Session struct {
	conn         *quic.Conn
	ctx          context.Context
	cancel       context.CancelFunc
	egress       map[uint8]*udpEgress
	ingress      map[uint8]*udpIngress
	lastMTUWarns atomic.Int64
	closeOnce    sync.Once
	wg           sync.WaitGroup
}

// Manager owns long-lived local TCP/UDP listeners and routes them through the
// currently active QUIC Session, surviving disconnects and reconnects without
// rebinding local ports.
type Manager struct {
	role        string
	forwards    []config.PortForward
	udpSpecs    []UDPChannelSpec
	udpIngress  map[uint8]*udpIngress
	tcpListens  []net.Listener
	listenAddrs map[string]string

	mu      sync.RWMutex
	session *Session

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager initializes local TCP and UDP forward listeners for the given role and rules.
// Client-owned UDP channels use IDs 1..127; server-owned UDP channels use IDs 128..254.
func NewManager(parentCtx context.Context, role string, forwards []config.PortForward) (*Manager, error) {
	ctx, cancel := context.WithCancel(parentCtx)
	m := &Manager{
		role:        role,
		forwards:    forwards,
		udpIngress:  make(map[uint8]*udpIngress),
		listenAddrs: make(map[string]string, len(forwards)),
		ctx:         ctx,
		cancel:      cancel,
	}

	nextID := uint8(1)
	if role == config.RoleServer {
		nextID = 128
	}

	for _, f := range forwards {
		switch f.Proto {
		case config.ProtoTCP:
			ln, err := net.Listen("tcp", f.Listen)
			if err != nil {
				m.Close()
				return nil, fmt.Errorf("listen tcp %s (%s): %w", f.Listen, f.Name, err)
			}
			m.tcpListens = append(m.tcpListens, ln)
			m.listenAddrs[f.Name] = ln.Addr().String()
			m.wg.Add(1)
			go m.serveTCPListener(ln, f)
			slog.Info("local TCP forward ready", "name", f.Name, "listen", ln.Addr().String(), "target", f.Target)

		case config.ProtoUDP:
			if (role == config.RoleClient && nextID > 127) || (role == config.RoleServer && nextID == 255) {
				m.Close()
				return nil, fmt.Errorf("too many UDP forwards for role %s (max 127)", role)
			}
			udpAddr, err := net.ResolveUDPAddr("udp", f.Listen)
			if err != nil {
				m.Close()
				return nil, fmt.Errorf("resolve udp %s (%s): %w", f.Listen, f.Name, err)
			}
			pc, err := net.ListenUDP("udp", udpAddr)
			if err != nil {
				m.Close()
				return nil, fmt.Errorf("listen udp %s (%s): %w", f.Listen, f.Name, err)
			}
			id := nextID
			nextID++
			ing := &udpIngress{id: id, spec: f, conn: pc}
			m.udpIngress[id] = ing
			m.listenAddrs[f.Name] = pc.LocalAddr().String()
			m.udpSpecs = append(m.udpSpecs, UDPChannelSpec{
				ID:     id,
				Name:   f.Name,
				Target: f.Target,
			})
			m.wg.Add(1)
			go m.serveUDPIngress(ing)
			slog.Info("local UDP forward ready (RFC 9221 Datagram)",
				"name", f.Name,
				"channel_id", id,
				"listen", pc.LocalAddr().String(),
				"target", f.Target,
			)
		}
	}

	return m, nil
}

// ListenAddr returns the bound local address for a named forward rule.
func (m *Manager) ListenAddr(name string) string {
	return m.listenAddrs[name]
}

// UDPChannels returns the local UDP forwarding specs to advertise during handshake.
func (m *Manager) UDPChannels() []UDPChannelSpec {
	out := make([]UDPChannelSpec, len(m.udpSpecs))
	copy(out, m.udpSpecs)
	return out
}

// Close shuts down all local listeners and any active tunnel session.
func (m *Manager) Close() {
	m.cancel()
	for _, ln := range m.tcpListens {
		_ = ln.Close()
	}
	for _, ing := range m.udpIngress {
		_ = ing.conn.Close()
	}
	m.mu.Lock()
	sess := m.session
	m.session = nil
	m.mu.Unlock()
	if sess != nil {
		sess.Close(errCodeNormalClose, "manager closing")
	}
	m.wg.Wait()
}

func (m *Manager) activeSession() *Session {
	m.mu.RLock()
	s := m.session
	m.mu.RUnlock()
	return s
}

// AttachSession activates a newly authenticated QUIC connection, replacing any
// stale previous session, and blocks until this session ends.
func (m *Manager) AttachSession(conn *quic.Conn, peerUDPChannels []UDPChannelSpec) error {
	sCtx, sCancel := context.WithCancel(m.ctx)
	sess := &Session{
		conn:    conn,
		ctx:     sCtx,
		cancel:  sCancel,
		egress:  make(map[uint8]*udpEgress, len(peerUDPChannels)),
		ingress: m.udpIngress,
	}

	for _, ch := range peerUDPChannels {
		raddr, err := net.ResolveUDPAddr("udp", ch.Target)
		if err != nil {
			sess.Close(errCodeNormalClose, "resolve udp target failed")
			return fmt.Errorf("resolve peer udp channel %d target %s: %w", ch.ID, ch.Target, err)
		}
		uconn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			sess.Close(errCodeNormalClose, "dial udp target failed")
			return fmt.Errorf("dial peer udp channel %d target %s: %w", ch.ID, ch.Target, err)
		}
		eg := &udpEgress{id: ch.ID, target: ch.Target, conn: uconn}
		sess.egress[ch.ID] = eg
		slog.Info("remote UDP egress ready", "channel_id", ch.ID, "name", ch.Name, "target", ch.Target)
	}

	// Swap in the new session and close any previous stale session.
	m.mu.Lock()
	prev := m.session
	m.session = sess
	m.mu.Unlock()
	if prev != nil {
		slog.Info("replacing previous tunnel session with new connection", "remote", conn.RemoteAddr().String())
		prev.Close(errCodeSessionSwap, "replaced by new session")
	}

	// Start egress read loops (target UDP -> QUIC Datagram).
	for _, eg := range sess.egress {
		sess.wg.Add(1)
		go sess.serveUDPEgress(eg)
	}

	errCh := make(chan error, 2)
	sess.wg.Add(2)
	go func() {
		defer sess.wg.Done()
		errCh <- sess.acceptTCPStreams()
	}()
	go func() {
		defer sess.wg.Done()
		errCh <- sess.recvDatagrams()
	}()

	var firstErr error
	select {
	case firstErr = <-errCh:
	case <-sCtx.Done():
	case <-conn.Context().Done():
		firstErr = context.Cause(conn.Context())
	}

	sess.Close(errCodeNormalClose, "session ended")

	// Clear m.session only if it still points to this session.
	m.mu.Lock()
	if m.session == sess {
		m.session = nil
	}
	m.mu.Unlock()

	return firstErr
}

// HandshakeServer authenticates an incoming QUIC connection and returns the peer's UDP channels.
func HandshakeServer(ctx context.Context, conn *quic.Conn, expectedPSK string, localUDP []UDPChannelSpec) ([]UDPChannelSpec, error) {
	if !conn.ConnectionState().SupportsDatagrams.Remote {
		_ = conn.CloseWithError(errCodeAuthFailed, "")
		return nil, errors.New("peer does not support RFC 9221 QUIC Datagrams")
	}

	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ctrl, err := conn.AcceptStream(hsCtx)
	if err != nil {
		return nil, fmt.Errorf("accept auth stream: %w", err)
	}
	defer ctrl.Close()

	var req AuthRequest
	if err := readJSON(ctrl, &req); err != nil {
		_ = conn.CloseWithError(errCodeAuthFailed, "")
		return nil, fmt.Errorf("read auth request: %w", err)
	}

	if !ConstantTimePSKMatch(req.PSK, expectedPSK) {
		_ = writeJSON(ctrl, AuthResponse{OK: false, Error: "unauthorized"})
		_ = conn.CloseWithError(errCodeAuthFailed, "")
		return nil, errors.New("invalid PSK")
	}

	if err := writeJSON(ctrl, AuthResponse{OK: true, UDPChannels: localUDP}); err != nil {
		return nil, fmt.Errorf("write auth response: %w", err)
	}
	return req.UDPChannels, nil
}

// HandshakeClient authenticates an outgoing QUIC connection and returns the server's UDP channels.
func HandshakeClient(ctx context.Context, conn *quic.Conn, psk string, localUDP []UDPChannelSpec) ([]UDPChannelSpec, error) {
	if !conn.ConnectionState().SupportsDatagrams.Remote {
		return nil, errors.New("server does not support RFC 9221 QUIC Datagrams")
	}

	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	ctrl, err := conn.OpenStreamSync(hsCtx)
	if err != nil {
		return nil, fmt.Errorf("open auth stream: %w", err)
	}
	defer ctrl.Close()

	if err := writeJSON(ctrl, AuthRequest{PSK: psk, UDPChannels: localUDP}); err != nil {
		return nil, fmt.Errorf("write auth request: %w", err)
	}

	var resp AuthResponse
	if err := readJSON(ctrl, &resp); err != nil {
		return nil, fmt.Errorf("read auth response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("server rejected auth: %s", resp.Error)
	}
	return resp.UDPChannels, nil
}

func (m *Manager) serveTCPListener(ln net.Listener, f config.PortForward) {
	defer m.wg.Done()
	for {
		localConn, err := ln.Accept()
		if err != nil {
			if m.ctx.Err() != nil {
				return
			}
			slog.Warn("local TCP accept error", "name", f.Name, "err", err)
			continue
		}
		go m.handleLocalTCP(localConn, f)
	}
}

func (m *Manager) handleLocalTCP(localConn net.Conn, f config.PortForward) {
	defer localConn.Close()
	sess := m.activeSession()
	if sess == nil {
		slog.Warn("dropping local TCP connection: no active tunnel session", "name", f.Name)
		return
	}

	openCtx, cancel := context.WithTimeout(sess.ctx, tcpDialTimeout)
	stream, err := sess.conn.OpenStreamSync(openCtx)
	cancel()
	if err != nil {
		slog.Warn("open QUIC stream failed", "name", f.Name, "err", err)
		return
	}
	defer stream.Close()

	if err := writeTCPStreamHeader(stream, f.Target); err != nil {
		slog.Warn("write TCP stream header failed", "name", f.Name, "err", err)
		return
	}
	if err := readStreamStatus(stream); err != nil {
		slog.Warn("peer target dial failed", "name", f.Name, "target", f.Target, "err", err)
		return
	}

	pipeBidirectional(localConn, stream)
}

func (m *Manager) serveUDPIngress(ing *udpIngress) {
	defer m.wg.Done()
	buf := make([]byte, udpReadBufSize)
	for {
		n, clientAddr, err := ing.conn.ReadFromUDP(buf[1:])
		if err != nil {
			if m.ctx.Err() != nil {
				return
			}
			slog.Warn("local UDP read error", "name", ing.spec.Name, "err", err)
			continue
		}
		ing.setClient(clientAddr)

		sess := m.activeSession()
		if sess == nil {
			continue
		}
		buf[0] = ing.id
		sess.sendDatagram(buf[:1+n], ing.spec.Name)
	}
}

func (s *Session) Close(code quic.ApplicationErrorCode, reason string) {
	s.closeOnce.Do(func() {
		s.cancel()
		for _, eg := range s.egress {
			_ = eg.conn.Close()
		}
		_ = s.conn.CloseWithError(code, reason)
	})
	s.wg.Wait()
}

func (s *Session) sendDatagram(pkt []byte, name string) {
	err := s.conn.SendDatagram(pkt)
	if err == nil {
		return
	}
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		now := time.Now().UnixNano()
		prev := s.lastMTUWarns.Load()
		if now-prev >= int64(mtuWarnCooldown) && s.lastMTUWarns.CompareAndSwap(prev, now) {
			slog.Warn("QUIC datagram dropped: payload exceeds path MaxDatagramSize",
				"forward", name,
				"payload_bytes", len(pkt),
				"max_datagram_size", tooLarge.MaxDatagramPayloadSize,
			)
		}
		return
	}
	if s.ctx.Err() == nil {
		slog.Debug("send datagram error", "forward", name, "err", err)
	}
}

func (s *Session) acceptTCPStreams() error {
	for {
		stream, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			return err
		}
		go s.handleRemoteTCPStream(stream)
	}
}

func (s *Session) handleRemoteTCPStream(stream *quic.Stream) {
	defer stream.Close()
	target, err := readTCPStreamHeader(stream)
	if err != nil {
		slog.Warn("read TCP stream header error", "err", err)
		return
	}

	targetConn, err := net.DialTimeout("tcp", target, tcpDialTimeout)
	if err != nil {
		slog.Warn("dial local TCP target failed", "target", target, "err", err)
		_ = writeStreamStatus(stream, false)
		return
	}
	defer targetConn.Close()

	if err := writeStreamStatus(stream, true); err != nil {
		return
	}

	pipeBidirectional(targetConn, stream)
}

func (s *Session) recvDatagrams() error {
	for {
		pkt, err := s.conn.ReceiveDatagram(s.ctx)
		if err != nil {
			return err
		}
		if len(pkt) < 2 {
			continue
		}
		id := pkt[0]
		payload := pkt[1:]

		if ing, ok := s.ingress[id]; ok {
			if client := ing.getClient(); client != nil {
				_, _ = ing.conn.WriteToUDP(payload, client)
			}
			continue
		}
		if eg, ok := s.egress[id]; ok {
			_, _ = eg.conn.Write(payload)
			continue
		}
	}
}

func (s *Session) serveUDPEgress(eg *udpEgress) {
	defer s.wg.Done()
	buf := make([]byte, udpReadBufSize)
	for {
		n, err := eg.conn.Read(buf[1:])
		if err != nil {
			if s.ctx.Err() != nil {
				return
			}
			slog.Debug("UDP egress read error", "channel_id", eg.id, "target", eg.target, "err", err)
			continue
		}
		buf[0] = eg.id
		s.sendDatagram(buf[:1+n], eg.target)
	}
}

func pipeBidirectional(conn net.Conn, stream *quic.Stream) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, conn)
		_ = stream.Close()
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, stream)
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()
}
