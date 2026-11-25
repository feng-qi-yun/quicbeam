package forward

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/feng-qi-yun/quicbeam/internal/config"
	"github.com/feng-qi-yun/quicbeam/internal/signal"
	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

// RunServer starts a QUIC tunnel server, binds any configured local forwards,
// optionally publishes its public endpoint via shared-socket STUN + encrypted
// signaling (with bidirectional NAT hole punching), authenticates incoming
// peer connections via PSK, and serves until ctx is canceled.
func RunServer(ctx context.Context, cfg *config.Config) error {
	tlsCfg, ephemeral, err := transport.BuildServerTLSConfig(transport.ServerTLSOptions{
		CertFile:   cfg.CertFile,
		KeyFile:    cfg.KeyFile,
		ServerName: cfg.ServerName,
		ALPN:       cfg.ALPN,
	})
	if err != nil {
		return err
	}
	if ephemeral {
		slog.Info("tunnel server using ephemeral self-signed TLS 1.3 cert",
			"sni", cfg.ServerName,
			"alpn", tlsCfg.NextProtos,
		)
	}

	mgr, err := NewManager(ctx, config.RoleServer, cfg.Forwards)
	if err != nil {
		return err
	}
	mgr.SetAllowedTargets(cfg.AllowedTargets)
	defer mgr.Close()

	hasSignal := cfg.Signal != nil && cfg.Signal.URL != ""
	if hasSignal {
		rawPC, err := net.ListenPacket("udp", cfg.ListenAddr)
		if err != nil {
			return fmt.Errorf("listen udp %s: %w", cfg.ListenAddr, err)
		}
		demux := signal.NewDemuxPacketConn(rawPC)
		defer demux.Close()

		ln, tr, err := transport.ListenOnConn(demux, tlsCfg, transport.DefaultQUICConfig())
		if err != nil {
			return err
		}
		defer tr.Close()
		defer ln.Close()

		listenPort := extractListenPort(ln.Addr().String(), 443)
		go runSignalPublisher(ctx, demux, cfg.Signal, cfg.PSK, config.RoleServer, listenPort)
		if cfg.Signal.HolePunch {
			go runServerPunchPoller(ctx, demux, cfg.Signal, cfg.PSK)
		}
		return ServeListener(ctx, ln, cfg.PSK, mgr)
	}

	ln, err := transport.Listen(cfg.ListenAddr, tlsCfg, transport.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer ln.Close()

	return ServeListener(ctx, ln, cfg.PSK, mgr)
}

// ServeListener accepts incoming QUIC connections on ln, performs PSK handshake,
// and attaches authenticated sessions to mgr until ctx is canceled.
func ServeListener(ctx context.Context, ln *quic.Listener, psk string, mgr *Manager) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept quic conn: %w", err)
		}

		go func(c *quic.Conn) {
			peerUDP, err := HandshakeServer(ctx, c, psk, mgr.UDPChannels())
			if err != nil {
				slog.Warn("tunnel auth rejected", "remote", c.RemoteAddr().String(), "err", err)
				return
			}
			slog.Info("tunnel peer authenticated",
				"remote", c.RemoteAddr().String(),
				"peer_udp_channels", len(peerUDP),
				"local_udp_channels", len(mgr.UDPChannels()),
			)
			if err := mgr.AttachSession(c, peerUDP); err != nil && ctx.Err() == nil {
				slog.Info("tunnel session disconnected", "remote", c.RemoteAddr().String(), "err", err)
			}
		}(conn)
	}
}

// RunClient starts a QUIC tunnel client, binds any configured local forwards,
// resolves the server endpoint (static or via encrypted signaling), optionally
// performs shared-socket UDP NAT hole punching, dials over QUIC with optional
// Make-Before-Break Port Hopping, and reconnects with exponential backoff.
func RunClient(ctx context.Context, cfg *config.Config) error {
	mgr, err := NewManager(ctx, config.RoleClient, cfg.Forwards)
	if err != nil {
		return err
	}
	mgr.SetAllowedTargets(cfg.AllowedTargets)
	defer mgr.Close()

	tlsCfg := transport.BuildClientTLSConfig(transport.ClientTLSOptions{
		ServerName:         cfg.ServerName,
		ALPN:               cfg.ALPN,
		CertSHA256:         cfg.CertSHA256,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})

	var sigClient *signal.Client
	if cfg.Signal != nil && cfg.Signal.URL != "" {
		sigClient = signal.NewClient(cfg.Signal, cfg.PSK)
	}

	backoff := 1 * time.Second
	const maxBackoff = 10 * time.Second

	for {
		if ctx.Err() != nil {
			return nil
		}

		candidates := resolveDialCandidates(ctx, cfg, sigClient)
		if len(candidates) == 0 {
			slog.Warn("no remote endpoint candidates available, retrying", "backoff", backoff)
			if !sleepWithContext(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		var (
			dc      *transport.DialedConn
			dialErr error
		)

		if sigClient != nil && cfg.Signal.HolePunch {
			dc, dialErr = dialWithHolePunch(ctx, cfg, sigClient, candidates, tlsCfg)
		} else {
			for _, target := range candidates {
				dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				dc, dialErr = transport.DialWithTransport(dialCtx, target, tlsCfg, transport.DefaultQUICConfig())
				cancel()
				if dialErr == nil {
					break
				}
				if ctx.Err() != nil {
					return nil
				}
				slog.Warn("tunnel dial attempt failed", "remote", target, "err", dialErr)
			}
		}

		if dc == nil {
			slog.Warn("all dial candidates failed, retrying", "backoff", backoff, "err", dialErr)
			if !sleepWithContext(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		hopper := transport.NewPortHopper(dc, time.Duration(cfg.PortHopIntervalSec)*time.Second)

		peerUDP, err := HandshakeClient(ctx, dc.Conn, cfg.PSK, mgr.UDPChannels())
		if err != nil {
			_ = dc.Conn.CloseWithError(errCodeAuthFailed, "handshake failed")
			hopper.Close()
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("tunnel handshake failed, retrying", "remote", dc.Conn.RemoteAddr().String(), "backoff", backoff, "err", err)
			if !sleepWithContext(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		backoff = 1 * time.Second
		slog.Info("tunnel established",
			"remote", dc.Conn.RemoteAddr().String(),
			"peer_udp_channels", len(peerUDP),
			"local_udp_channels", len(mgr.UDPChannels()),
			"port_hop_sec", cfg.PortHopIntervalSec,
		)

		hopCtx, cancelHop := context.WithCancel(ctx)
		if cfg.PortHopIntervalSec > 0 {
			go hopper.Run(hopCtx)
		}

		if err := mgr.AttachSession(dc.Conn, peerUDP); err != nil && ctx.Err() == nil {
			slog.Warn("tunnel session lost, reconnecting", "err", err)
		}

		cancelHop()
		hopper.Close()

		if !sleepWithContext(ctx, backoff) {
			return nil
		}
	}
}

// dialWithHolePunch probes STUN on a fresh local UDP socket, publishes that exact
// external IP:Port to signaling so the server punches back, sends an outbound punch
// burst, and dials QUIC on the exact same UDP socket.
func dialWithHolePunch(
	ctx context.Context,
	cfg *config.Config,
	sigClient *signal.Client,
	candidates []string,
	tlsCfg *tls.Config,
) (*transport.DialedConn, error) {
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("bind local udp4 for hole punch: %w", err)
	}

	stunCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	mapped, stunSrv, stunErr := signal.QuerySTUNOnPacketConn(stunCtx, pc, cfg.Signal.STUNServers)
	cancel()
	if stunErr != nil {
		slog.Warn("client same-socket STUN failed, proceeding with direct dial", "err", stunErr)
	} else {
		ep := &signal.PeerEndpoint{
			Role:      config.RoleClient,
			IPv4:      mapped.IP.String(),
			Port:      mapped.Port,
			IPv6:      signal.LocalGlobalIPv6(),
			UpdatedAt: time.Now().UTC(),
		}
		pubCtx, pubCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := sigClient.Publish(pubCtx, ep); err != nil {
			slog.Warn("client publish punch endpoint failed", "err", err)
		} else {
			slog.Info("published client punch endpoint",
				"external", mapped.String(),
				"local", pc.LocalAddr().String(),
				"stun_server", stunSrv,
			)
		}
		pubCancel()
	}

	var lastErr error
	for _, target := range candidates {
		// Send punch burst to open outbound Cone NAT mapping before QUIC Initial.
		if err := signal.SendPunchBurst(pc, target, 4); err != nil {
			slog.Debug("client punch burst error", "target", target, "err", err)
		}

		dialCtx, dCancel := context.WithTimeout(ctx, 10*time.Second)
		dc, err := transport.DialOnConn(dialCtx, pc, target, tlsCfg, transport.DefaultQUICConfig())
		dCancel()
		if err == nil {
			return dc, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
		slog.Warn("hole-punch dial attempt failed", "remote", target, "err", err)
	}

	_ = pc.Close()
	return nil, lastErr
}

func resolveDialCandidates(ctx context.Context, cfg *config.Config, sigClient *signal.Client) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(addr string) {
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; !ok {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}

	if sigClient != nil {
		fetchCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		ep, err := sigClient.FetchPeer(fetchCtx, config.RoleServer)
		cancel()
		if err != nil {
			slog.Warn("signal fetch server endpoint failed", "err", err)
		} else {
			slog.Info("signal resolved server endpoint",
				"ipv4", ep.IPv4,
				"ipv6_count", len(ep.IPv6),
				"port", ep.Port,
				"updated_at", ep.UpdatedAt.Format(time.RFC3339),
			)
			for _, c := range ep.CandidateAddrs(cfg.Signal.PreferIPv6) {
				add(c)
			}
		}
	}

	add(cfg.RemoteAddr)
	return out
}

func runSignalPublisher(ctx context.Context, demux *signal.DemuxPacketConn, sigCfg *config.SignalConfig, psk, role string, listenPort int) {
	client := signal.NewClient(sigCfg, psk)
	interval := time.Duration(sigCfg.PublishIntervalSec) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	var lastPublished string
	publishOnce := func() {
		pCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		ipv6 := signal.LocalGlobalIPv6()
		mapped, stunSrv, err := demux.DiscoverPublicIPv4(pCtx, sigCfg.STUNServers)
		if err != nil && len(ipv6) == 0 {
			slog.Warn("shared-socket STUN discovery failed", "err", err)
			return
		}

		ep := &signal.PeerEndpoint{
			Role:      role,
			Port:      listenPort,
			IPv6:      ipv6,
			UpdatedAt: time.Now().UTC(),
		}
		if mapped != nil {
			ep.IPv4 = mapped.IP.String()
			// In hole-punch mode (behind Cone NAT without port forwarding), advertise
			// the exact NAT-mapped external port of the listening socket.
			if sigCfg.HolePunch && mapped.Port > 0 {
				ep.Port = mapped.Port
			}
		}

		if err := client.Publish(pCtx, ep); err != nil {
			slog.Warn("signal publish endpoint failed", "err", err)
			return
		}
		key := fmt.Sprintf("%s:%d", ep.IPv4, ep.Port)
		if key != lastPublished {
			slog.Info("published public endpoint to signaling service",
				"ipv4", ep.IPv4,
				"port", ep.Port,
				"ipv6_count", len(ep.IPv6),
				"stun_server", stunSrv,
				"hole_punch", sigCfg.HolePunch,
			)
			lastPublished = key
		}
	}

	publishOnce()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publishOnce()
		}
	}
}

func runServerPunchPoller(ctx context.Context, demux *signal.DemuxPacketConn, sigCfg *config.SignalConfig, psk string) {
	client := signal.NewClient(sigCfg, psk)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	var lastClientUpdated time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			ep, err := client.FetchPeer(fCtx, config.RoleClient)
			cancel()
			if err != nil || ep == nil {
				continue
			}
			if !ep.UpdatedAt.After(lastClientUpdated) || time.Since(ep.UpdatedAt) > 60*time.Second {
				continue
			}
			lastClientUpdated = ep.UpdatedAt
			for _, addr := range ep.CandidateAddrs(sigCfg.PreferIPv6) {
				slog.Info("sending NAT hole-punch burst to client", "client_addr", addr)
				if err := signal.SendPunchBurst(demux, addr, 5); err != nil {
					slog.Warn("server NAT punch burst failed", "client_addr", addr, "err", err)
				}
			}
		}
	}
}

func extractListenPort(addr string, fallback int) int {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 {
		return fallback
	}
	return p
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
