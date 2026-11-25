package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
)

const (
	RoleServer = "server"
	RoleClient = "client"

	ProtoTCP = "tcp"
	ProtoUDP = "udp"
)

// DefaultSTUNServers are used when SignalConfig.STUNServers is omitted.
var DefaultSTUNServers = []string{
	"stun.miwifi.com:3478",
	"stun.chat.bilibili.com:3478",
	"stun.cloudflare.com:3478",
}

// SignalConfig configures STUN endpoint discovery, encrypted HTTP/KV signaling,
// and shared-socket dual-NAT UDP hole punching.
type SignalConfig struct {
	URL                string   `json:"url"`                            // base URL, e.g. "https://signal.example.workers.dev"
	Room               string   `json:"room"`                           // logical tunnel room name
	Token              string   `json:"token,omitempty"`                // optional HTTP Bearer token
	STUNServers        []string `json:"stun_servers,omitempty"`
	PublishIntervalSec int      `json:"publish_interval_sec,omitempty"` // default 60
	PreferIPv6         bool     `json:"prefer_ipv6,omitempty"`
	HolePunch          bool     `json:"hole_punch,omitempty"`           // enable shared-socket STUN + bidirectional UDP hole punching
}

// PortForward defines a single TCP or UDP port forwarding mapping over the QUIC tunnel.
type PortForward struct {
	Name   string `json:"name"`
	Proto  string `json:"proto"`  // "tcp" (QUIC Stream) or "udp" (QUIC Datagram)
	Listen string `json:"listen"` // local bind address, e.g. "127.0.0.1:47998"
	Target string `json:"target"` // remote target address, e.g. "127.0.0.1:47998"
}

// Config holds the runtime configuration for quicbeam server or client.
type Config struct {
	Role               string        `json:"role"`                            // "server" or "client"
	ListenAddr         string        `json:"listen_addr"`                     // e.g. ":443" (server mode)
	RemoteAddr         string        `json:"remote_addr"`                     // peer address (client mode; optional if signal.url is set)
	ServerName         string        `json:"server_name"`                     // TLS SNI, default "www.cloudflare.com"
	ALPN               string        `json:"alpn"`                            // default "h3"
	CertFile           string        `json:"cert_file"`                       // optional PEM cert (server mode)
	KeyFile            string        `json:"key_file"`                        // optional PEM key (server mode)
	CertSHA256         string        `json:"cert_sha256,omitempty"`           // pinned server cert SHA-256 hex (client mode, replaces insecure_skip_verify)
	InsecureSkipVerify bool          `json:"insecure_skip_verify"`            // skip TLS cert check (dev only; prefer cert_sha256)
	PSK                string        `json:"psk"`                             // pre-shared key for session auth & signal encryption
	PortHopIntervalSec int           `json:"port_hop_interval_sec,omitempty"` // client Make-Before-Break port hopping interval (0 = disabled)
	AllowedTargets     []string      `json:"allowed_targets,omitempty"`       // egress target host/CIDR whitelist (empty = loopback only; "*" = allow all)
	Signal             *SignalConfig `json:"signal,omitempty"`                // optional STUN + encrypted signaling config
	Forwards           []PortForward `json:"forwards"`                        // local ports to listen and forward to peer
}

// Load reads, parses, and validates a JSON configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config %s: %w", path, err)
	}
	return &cfg, nil
}

// Validate checks required fields and applies safe defaults.
func (c *Config) Validate() error {
	c.Role = strings.ToLower(strings.TrimSpace(c.Role))
	if c.Role != "" && c.Role != RoleServer && c.Role != RoleClient {
		return fmt.Errorf("invalid role %q (must be %q or %q)", c.Role, RoleServer, RoleClient)
	}
	if c.ALPN == "" {
		c.ALPN = "h3"
	}
	if c.ServerName == "" {
		c.ServerName = "www.cloudflare.com"
	}
	if c.Role == RoleServer && c.ListenAddr == "" {
		c.ListenAddr = ":443"
	}
	if c.PortHopIntervalSec < 0 {
		return fmt.Errorf("port_hop_interval_sec must be >= 0")
	}
	if c.CertSHA256 != "" {
		clean := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c.CertSHA256), ":", ""))
		if len(clean) != 64 {
			return fmt.Errorf("cert_sha256 must be a 64-char hex SHA-256 fingerprint, got %d chars", len(clean))
		}
		c.CertSHA256 = clean
	}

	hasSignal := c.Signal != nil && strings.TrimSpace(c.Signal.URL) != ""
	if hasSignal {
		c.Signal.URL = strings.TrimRight(strings.TrimSpace(c.Signal.URL), "/")
		c.Signal.Room = strings.TrimSpace(c.Signal.Room)
		if c.Signal.Room == "" {
			return fmt.Errorf("signal.room is required when signal.url is set")
		}
		if c.Signal.PublishIntervalSec <= 0 {
			c.Signal.PublishIntervalSec = 60
		}
		if len(c.Signal.STUNServers) == 0 {
			c.Signal.STUNServers = append([]string(nil), DefaultSTUNServers...)
		}
	}

	if c.Role == RoleClient && c.RemoteAddr == "" && !hasSignal {
		return fmt.Errorf("remote_addr is required in client mode when signal.url is not configured")
	}
	if (c.CertFile != "" && c.KeyFile == "") || (c.CertFile == "" && c.KeyFile != "") {
		return fmt.Errorf("cert_file and key_file must be specified together")
	}
	if strings.TrimSpace(c.PSK) == "" {
		return fmt.Errorf("psk must not be empty")
	}

	udpCount := 0
	for i := range c.Forwards {
		f := &c.Forwards[i]
		f.Proto = strings.ToLower(strings.TrimSpace(f.Proto))
		if f.Proto != ProtoTCP && f.Proto != ProtoUDP {
			return fmt.Errorf("forwards[%d] (%s): invalid proto %q (must be tcp or udp)", i, f.Name, f.Proto)
		}
		if _, _, err := net.SplitHostPort(f.Listen); err != nil {
			return fmt.Errorf("forwards[%d] (%s): invalid listen addr %q: %w", i, f.Name, f.Listen, err)
		}
		if _, _, err := net.SplitHostPort(f.Target); err != nil {
			return fmt.Errorf("forwards[%d] (%s): invalid target addr %q: %w", i, f.Name, f.Target, err)
		}
		if f.Name == "" {
			f.Name = fmt.Sprintf("%s-%s", f.Proto, f.Listen)
		}
		if f.Proto == ProtoUDP {
			udpCount++
		}
	}
	if udpCount > 127 {
		return fmt.Errorf("too many UDP forwards (%d): maximum supported per peer is 127", udpCount)
	}
	return nil
}

// IsTargetAllowed reports whether target (host:port) is permitted by allowedTargets.
// When allowedTargets is empty, only loopback targets (127.0.0.0/8, ::1, localhost) are allowed.
func IsTargetAllowed(target string, allowedTargets []string) bool {
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	host = strings.TrimSpace(host)
	ip := net.ParseIP(host)

	if len(allowedTargets) == 0 {
		if strings.EqualFold(host, "localhost") {
			return true
		}
		return ip != nil && ip.IsLoopback()
	}

	for _, rule := range allowedTargets {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if rule == "*" {
			return true
		}
		if strings.EqualFold(rule, host) {
			return true
		}
		if ip != nil {
			if _, cidr, err := net.ParseCIDR(rule); err == nil && cidr.Contains(ip) {
				return true
			}
			if ruleIP := net.ParseIP(rule); ruleIP != nil && ruleIP.Equal(ip) {
				return true
			}
		}
	}
	return false
}
