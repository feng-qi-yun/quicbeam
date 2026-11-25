package forward

import (
	"context"
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
// optionally publishes its public endpoint via STUN + encrypted signaling,
// authenticates incoming peer connections via PSK, and serves until ctx is canceled.
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
	defer mgr.Close()

	ln, err := transport.Listen(cfg.ListenAddr, tlsCfg, transport.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer ln.Close()

	if cfg.Signal != nil && cfg.Signal.URL != "" {
		listenPort := extractListenPort(ln.Addr().String(), 443)
		go runSignalPublisher(ctx, cfg.Signal, cfg.PSK, config.RoleServer, listenPort)
	}

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
// resolves the server endpoint (static or via encrypted signaling), dials over
// QUIC with optional Make-Before-Break Port Hopping, and reconnects with
// exponential backoff until ctx is canceled.
func RunClient(ctx context.Context, cfg *config.Config) error {
	mgr, err := NewManager(ctx, config.RoleClient, cfg.Forwards)
	if err != nil {
		return err
	}
	defer mgr.Close()

	tlsCfg := transport.BuildClientTLSConfig(transport.ClientTLSOptions{
		ServerName:         cfg.ServerName,
		ALPN:               cfg.ALPN,
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

		// Reset backoff on successful authenticated session.
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

	// Always include static remote_addr as fallback if configured.
	add(cfg.RemoteAddr)
	return out
}

func runSignalPublisher(ctx context.Context, sigCfg *config.SignalConfig, psk, role string, listenPort int) {
	client := signal.NewClient(sigCfg, psk)
	interval := time.Duration(sigCfg.PublishIntervalSec) * time.Second
	if interval <= 0 {
		interval = 60 * time.Second
	}

	var lastIPv4 string
	publishOnce := func() {
		pCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()

		ep, stunSrv, err := signal.DiscoverEndpoint(pCtx, role, listenPort, sigCfg.STUNServers)
		if err != nil {
			slog.Warn("STUN endpoint discovery failed", "err", err)
			return
		}
		if err := client.Publish(pCtx, ep); err != nil {
			slog.Warn("signal publish endpoint failed", "err", err)
			return
		}
		if ep.IPv4 != lastIPv4 {
			slog.Info("published public endpoint to signaling service",
				"ipv4", ep.IPv4,
				"port", ep.Port,
				"ipv6_count", len(ep.IPv6),
				"stun_server", stunSrv,
			)
			lastIPv4 = ep.IPv4
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
