package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/feng-qi-yun/quicbeam/internal/config"
	"github.com/feng-qi-yun/quicbeam/internal/forward"
	"github.com/feng-qi-yun/quicbeam/internal/probe"
	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

const version = "0.1.0-dev"

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

func printUsage() {
	fmt.Println(`quicbeam - Anti-DPI QUIC (UDP 443 / RFC 9221 Datagram) P2P tunnel for low-latency streaming

Usage:
  quicbeam <command> [flags]

Commands:
  server    Run tunnel server (home desktop / Sunshine host)
  client    Run tunnel client (laptop / Moonlight client)
  probe     Benchmark sustained UDP 443 QUIC Datagram / Stream throughput
  version   Print version information`)
}
