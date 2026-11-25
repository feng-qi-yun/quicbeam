package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidateAndDefaults(t *testing.T) {
	cfg := &Config{
		Role: "server",
		PSK:  "test-secret-psk",
		Forwards: []PortForward{
			{Name: "ssh", Proto: "TCP", Listen: "127.0.0.1:2222", Target: "127.0.0.1:22"},
			{Name: "video", Proto: "udp", Listen: "127.0.0.1:47998", Target: "127.0.0.1:47998"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if cfg.ListenAddr != ":443" {
		t.Fatalf("expected default listen_addr :443, got %q", cfg.ListenAddr)
	}
	if cfg.ALPN != "h3" {
		t.Fatalf("expected default alpn h3, got %q", cfg.ALPN)
	}
	if cfg.Forwards[0].Proto != ProtoTCP {
		t.Fatalf("expected normalized proto tcp, got %q", cfg.Forwards[0].Proto)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing psk",
			cfg:  Config{Role: "server"},
		},
		{
			name: "client missing remote",
			cfg:  Config{Role: "client", PSK: "abc"},
		},
		{
			name: "bad proto",
			cfg: Config{
				Role: "server",
				PSK:  "abc",
				Forwards: []PortForward{
					{Proto: "icmp", Listen: "127.0.0.1:1000", Target: "127.0.0.1:1000"},
				},
			},
		},
		{
			name: "bad listen addr",
			cfg: Config{
				Role: "server",
				PSK:  "abc",
				Forwards: []PortForward{
					{Proto: "tcp", Listen: "invalid", Target: "127.0.0.1:22"},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := tc.cfg
			if err := c.Validate(); err == nil {
				t.Fatalf("expected error for %s, got nil", tc.name)
			}
		})
	}
}

func TestConfigLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.json")
	content := `{
		"role": "client",
		"remote_addr": "192.0.2.1:443",
		"psk": "dummy-psk",
		"insecure_skip_verify": true
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.RemoteAddr != "192.0.2.1:443" || !cfg.InsecureSkipVerify {
		t.Fatalf("unexpected loaded config: %+v", cfg)
	}
}

func TestConfigSignalDefaults(t *testing.T) {
	cfg := &Config{
		Role:               "client",
		PSK:                "secret",
		PortHopIntervalSec: 120,
		Signal: &SignalConfig{
			URL:  "https://signal.example.com/",
			Room: "home-desktop",
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected valid signal client config, got %v", err)
	}
	if cfg.Signal.URL != "https://signal.example.com" {
		t.Fatalf("expected trimmed URL, got %q", cfg.Signal.URL)
	}
	if cfg.Signal.PublishIntervalSec != 60 {
		t.Fatalf("expected default publish_interval_sec=60, got %d", cfg.Signal.PublishIntervalSec)
	}
	if len(cfg.Signal.STUNServers) == 0 {
		t.Fatalf("expected default STUN servers")
	}
}

func TestIsTargetAllowed(t *testing.T) {
	// Default (empty): loopback only.
	if !IsTargetAllowed("127.0.0.1:47984", nil) {
		t.Fatal("expected 127.0.0.1 allowed by default")
	}
	if !IsTargetAllowed("[::1]:22", nil) {
		t.Fatal("expected ::1 allowed by default")
	}
	if !IsTargetAllowed("localhost:22", nil) {
		t.Fatal("expected localhost allowed by default")
	}
	if IsTargetAllowed("192.168.1.3:22", nil) {
		t.Fatal("expected LAN IP blocked by default")
	}

	// Custom CIDR whitelist.
	rules := []string{"127.0.0.1", "192.168.1.0/24"}
	if !IsTargetAllowed("192.168.1.3:47998", rules) {
		t.Fatal("expected 192.168.1.3 allowed by CIDR")
	}
	if IsTargetAllowed("10.0.0.1:22", rules) {
		t.Fatal("expected 10.0.0.1 blocked by CIDR")
	}

	// Wildcard.
	if !IsTargetAllowed("10.0.0.1:22", []string{"*"}) {
		t.Fatal("expected wildcard to allow all")
	}
}
