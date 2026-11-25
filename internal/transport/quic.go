package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
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

// DialedConn bundles an established client QUIC connection with its underlying
// Transport and UDP socket so callers can perform Connection Migration (Port Hopping)
// and clean up all sockets on teardown.
type DialedConn struct {
	Conn      *quic.Conn
	Transport *quic.Transport
	UDPConn   *net.UDPConn
	Network   string // "udp4" or "udp6"
}

// DialWithTransport dials a QUIC server using an explicit *quic.Transport so the
// connection supports Make-Before-Break Connection Migration via PortHopper.
func DialWithTransport(ctx context.Context, addr string, tlsCfg *tls.Config, quicCfg *quic.Config) (*DialedConn, error) {
	if quicCfg == nil {
		quicCfg = DefaultQUICConfig()
	}
	raddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp %s: %w", addr, err)
	}
	network := "udp4"
	if raddr.IP != nil && raddr.IP.To4() == nil {
		network = "udp6"
	}

	pc, err := net.ListenUDP(network, &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen local %s: %w", network, err)
	}
	tr := &quic.Transport{Conn: pc}

	start := time.Now()
	conn, err := tr.Dial(ctx, raddr, tlsCfg, quicCfg)
	if err != nil {
		_ = tr.Close()
		_ = pc.Close()
		return nil, fmt.Errorf("quic dial %s: %w", addr, err)
	}

	state := conn.ConnectionState()
	slog.Info("quic connected",
		"remote_addr", conn.RemoteAddr().String(),
		"local_addr", pc.LocalAddr().String(),
		"handshake_ms", time.Since(start).Milliseconds(),
		"alpn", state.TLS.NegotiatedProtocol,
		"remote_datagrams", state.SupportsDatagrams.Remote,
	)
	return &DialedConn{
		Conn:      conn,
		Transport: tr,
		UDPConn:   pc,
		Network:   network,
	}, nil
}
