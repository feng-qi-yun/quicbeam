package forward

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/feng-qi-yun/quicbeam/internal/config"
	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

// RunServer starts a QUIC tunnel server, binds any configured local forwards,
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
// dials the remote server, and automatically reconnects with exponential backoff
// until ctx is canceled.
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

	backoff := 1 * time.Second
	const maxBackoff = 10 * time.Second

	for {
		if ctx.Err() != nil {
			return nil
		}

		dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		conn, err := transport.Dial(dialCtx, cfg.RemoteAddr, tlsCfg, transport.DefaultQUICConfig())
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("tunnel dial failed, retrying", "remote", cfg.RemoteAddr, "backoff", backoff, "err", err)
			if !sleepWithContext(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		peerUDP, err := HandshakeClient(ctx, conn, cfg.PSK, mgr.UDPChannels())
		if err != nil {
			_ = conn.CloseWithError(errCodeAuthFailed, "handshake failed")
			if ctx.Err() != nil {
				return nil
			}
			slog.Warn("tunnel handshake failed, retrying", "remote", cfg.RemoteAddr, "backoff", backoff, "err", err)
			if !sleepWithContext(ctx, backoff) {
				return nil
			}
			backoff = min(backoff*2, maxBackoff)
			continue
		}

		// Reset backoff on successful authenticated session.
		backoff = 1 * time.Second
		slog.Info("tunnel established",
			"remote", conn.RemoteAddr().String(),
			"peer_udp_channels", len(peerUDP),
			"local_udp_channels", len(mgr.UDPChannels()),
		)

		if err := mgr.AttachSession(conn, peerUDP); err != nil && ctx.Err() == nil {
			slog.Warn("tunnel session lost, reconnecting", "remote", cfg.RemoteAddr, "err", err)
		}

		if !sleepWithContext(ctx, backoff) {
			return nil
		}
	}
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
