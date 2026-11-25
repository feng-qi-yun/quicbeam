package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/feng-qi-yun/quicbeam/internal/config"
	"github.com/feng-qi-yun/quicbeam/internal/forward"
	"github.com/feng-qi-yun/quicbeam/internal/probe"
	qsignal "github.com/feng-qi-yun/quicbeam/internal/signal"
	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

const version = "0.3.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		if err := runTunnelCmd(config.RoleServer, os.Args[2:]); err != nil {
			slog.Error("server failed", "err", err)
			os.Exit(1)
		}
	case "client":
		if err := runTunnelCmd(config.RoleClient, os.Args[2:]); err != nil {
			slog.Error("client failed", "err", err)
			os.Exit(1)
		}
	case "probe":
		if err := runProbeCmd(os.Args[2:]); err != nil {
			slog.Error("probe failed", "err", err)
			os.Exit(1)
		}
	case "stun":
		if err := runStunCmd(os.Args[2:]); err != nil {
			slog.Error("stun failed", "err", err)
			os.Exit(1)
		}
	case "keygen":
		if err := runKeygenCmd(os.Args[2:]); err != nil {
			slog.Error("keygen failed", "err", err)
			os.Exit(1)
		}
	case "version", "-v", "--version":
		fmt.Printf("quicbeam %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runTunnelCmd(role string, args []string) error {
	fs := flag.NewFlagSet(role, flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to JSON config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *cfgPath == "" {
		fs.Usage()
		return fmt.Errorf("-config is required")
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Role == "" {
		cfg.Role = role
		if err := cfg.Validate(); err != nil {
			return err
		}
	} else if cfg.Role != role {
		return fmt.Errorf("config role is %q, but invoked as %q", cfg.Role, role)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if role == config.RoleServer {
		return forward.RunServer(ctx, cfg)
	}
	return forward.RunClient(ctx, cfg)
}

func runProbeCmd(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	isServer := fs.Bool("server", false, "run in probe server mode")
	listenAddr := fs.String("listen", ":443", "UDP listen address for server mode")
	remoteAddr := fs.String("remote", "", "remote server address (host:port) for client mode")
	proto := fs.String("proto", probe.ProtoDatagram, "probe transport mode: datagram or stream")
	dir := fs.String("dir", probe.DirUpload, "traffic direction: upload (client->server) or download (server->client)")
	duration := fs.Duration("duration", 15*time.Second, "probe duration (e.g. 15s)")
	rateMbps := fs.Float64("rate", 60, "target send rate in Mbps for datagram mode (0 = unpaced)")
	payloadBytes := fs.Int("payload", 1150, "datagram payload size in bytes")
	sni := fs.String("sni", transport.DefaultServerName, "TLS SNI server name")
	alpn := fs.String("alpn", transport.DefaultALPN, "TLS ALPN protocol")
	certFile := fs.String("cert", "", "TLS certificate PEM file (optional; ephemeral self-signed if empty)")
	keyFile := fs.String("key", "", "TLS private key PEM file (optional)")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification (for self-signed probe server)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *isServer {
		return probe.RunServer(ctx, probe.ServerOptions{
			ListenAddr: *listenAddr,
			ServerName: *sni,
			ALPN:       *alpn,
			CertFile:   *certFile,
			KeyFile:    *keyFile,
		})
	}

	if *remoteAddr == "" {
		fs.Usage()
		return fmt.Errorf("-remote is required in client mode (or pass -server)")
	}

	durSec := int(duration.Seconds())
	if durSec <= 0 {
		durSec = 1
	}

	report, err := probe.RunClient(ctx, probe.ClientOptions{
		RemoteAddr:         *remoteAddr,
		ServerName:         *sni,
		ALPN:               *alpn,
		InsecureSkipVerify: *insecure,
		Request: probe.Request{
			Proto:        *proto,
			Direction:    *dir,
			DurationSec:  durSec,
			PayloadBytes: *payloadBytes,
			RateMbps:     *rateMbps,
		},
	})
	if err != nil {
		return err
	}

	fmt.Print(probe.FormatReport(report))
	return nil
}

func runStunCmd(args []string) error {
	fs := flag.NewFlagSet("stun", flag.ExitOnError)
	server := fs.String("server", "", "specific STUN server host:port (uses built-in defaults if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	servers := config.DefaultSTUNServers
	if *server != "" {
		servers = []string{*server}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ep, stunSrv, err := qsignal.DiscoverEndpoint(ctx, "probe", 0, servers)
	if err != nil {
		return err
	}

	fmt.Printf("Public IPv4 : %s (port %d via %s)\n", ep.IPv4, ep.Port, stunSrv)
	if len(ep.IPv6) == 0 {
		fmt.Println("Global IPv6 : (none)")
	} else {
		for _, ip := range ep.IPv6 {
			fmt.Printf("Global IPv6 : %s\n", ip)
		}
	}
	return nil
}

func runKeygenCmd(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	outDir := fs.String("out-dir", ".", "output directory for server.crt and server.key")
	sni := fs.String("sni", transport.DefaultServerName, "certificate CommonName / DNS SAN")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	certPath := filepath.Join(*outDir, "server.crt")
	keyPath := filepath.Join(*outDir, "server.key")

	pin, err := transport.GenerateCertFiles(certPath, keyPath, *sni)
	if err != nil {
		return err
	}
	psk, err := transport.GenerateRandomPSK()
	if err != nil {
		return err
	}

	fmt.Printf("Cert file   : %s\n", certPath)
	fmt.Printf("Key file    : %s (mode 0600)\n", keyPath)
	fmt.Printf("cert_sha256 : %s\n", pin)
	fmt.Printf("psk         : %s\n", psk)
	return nil
}

func printUsage() {
	fmt.Println(`quicbeam - Anti-DPI QUIC (UDP 443 / RFC 9221 Datagram) P2P tunnel for low-latency streaming

Usage:
  quicbeam <command> [flags]

Commands:
  server    Run tunnel server (listen UDP 443 + optional STUN/signal/hole-punch)
  client    Run tunnel client (dial peer + optional signal/hole-punch/port-hopping)
  probe     Benchmark sustained UDP 443 QUIC Datagram / Stream throughput
  stun      Discover public IPv4 (STUN) and global IPv6 addresses
  keygen    Generate self-signed TLS 1.3 cert/key, SHA-256 pin, and random PSK
  version   Print version information`)
}
