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
