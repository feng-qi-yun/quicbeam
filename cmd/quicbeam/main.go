package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "server":
		fmt.Println("quicbeam server: not implemented yet (see docs/architecture.md)")
	case "client":
		fmt.Println("quicbeam client: not implemented yet (see docs/architecture.md)")
	case "probe":
		fmt.Println("quicbeam probe: not implemented yet (Phase 0 UDP 443 throughput probe)")
	case "version", "-v", "--version":
		fmt.Printf("quicbeam %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`quicbeam - Anti-DPI QUIC (UDP 443 / RFC 9221 Datagram) P2P tunnel for low-latency streaming

Usage:
  quicbeam <command> [flags]

Commands:
  server    Run tunnel server (home desktop / Sunshine host)
  client    Run tunnel client (laptop / Moonlight client)
  probe     Benchmark sustained UDP 443 QUIC Datagram throughput
  version   Print version information`)
}
