package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"time"

	"github.com/quic-go/quic-go"
)

// DefaultQUICConfig returns a QUIC configuration tuned for high-bandwidth,
// low-latency WAN streaming with RFC 9221 Unreliable Datagrams enabled.
func DefaultQUICConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		InitialStreamReceiveWindow:     4 * 1024 * 1024,  // 4 MiB
		MaxStreamReceiveWindow:         16 * 1024 * 1024, // 16 MiB
		InitialConnectionReceiveWindow: 8 * 1024 * 1024,  // 8 MiB
		MaxConnectionReceiveWindow:     32 * 1024 * 1024, // 32 MiB
		MaxIncomingStreams:             1024,
		MaxIncomingUniStreams:          1024,
	}
}

// Listen starts a QUIC listener on addr with the provided TLS and QUIC configs.
func Listen(addr string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Listener, error) {
	if quicCfg == nil {
		quicCfg = DefaultQUICConfig()
	}
	ln, err := quic.ListenAddr(addr, tlsCfg, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("quic listen %s: %w", addr, err)
	}
	slog.Info("quic listener started",
		"listen_addr", ln.Addr().String(),
		"alpn", tlsCfg.NextProtos,
		"datagrams", quicCfg.EnableDatagrams,
	)
	return ln, nil
}

// Dial establishes a QUIC connection to addr and logs handshake metrics.
func Dial(ctx context.Context, addr string, tlsCfg *tls.Config, quicCfg *quic.Config) (*quic.Conn, error) {
	if quicCfg == nil {
		quicCfg = DefaultQUICConfig()
	}
	start := time.Now()
	conn, err := quic.DialAddr(ctx, addr, tlsCfg, quicCfg)
	if err != nil {
		return nil, fmt.Errorf("quic dial %s: %w", addr, err)
	}
	state := conn.ConnectionState()
	slog.Info("quic connected",
		"remote_addr", conn.RemoteAddr().String(),
		"local_addr", conn.LocalAddr().String(),
		"handshake_ms", time.Since(start).Milliseconds(),
		"alpn", state.TLS.NegotiatedProtocol,
		"remote_datagrams", state.SupportsDatagrams.Remote,
	)
	return conn, nil
}
