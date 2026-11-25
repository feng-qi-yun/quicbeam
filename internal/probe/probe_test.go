package probe

import (
	"context"
	"testing"
	"time"

	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

func startTestServer(t *testing.T) (string, context.CancelFunc) {
	t.Helper()
	tlsCfg, _, err := transport.BuildServerTLSConfig(transport.ServerTLSOptions{
		ServerName: "localhost",
		ALPN:       transport.DefaultALPN,
	})
	if err != nil {
		t.Fatalf("build server tls config: %v", err)
	}
	ln, err := transport.Listen("127.0.0.1:0", tlsCfg, transport.DefaultQUICConfig())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = ServeListener(ctx, ln)
	}()
	t.Cleanup(func() {
		cancel()
		_ = ln.Close()
	})
	return ln.Addr().String(), cancel
}

func TestProbeDatagramUploadAndDownload(t *testing.T) {
	addr, _ := startTestServer(t)

	for _, dir := range []string{DirUpload, DirDownload} {
		t.Run(dir, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			report, err := RunClient(ctx, ClientOptions{
				RemoteAddr:         addr,
				ServerName:         "localhost",
				ALPN:               transport.DefaultALPN,
				InsecureSkipVerify: true,
				Request: Request{
					Proto:        ProtoDatagram,
					Direction:    dir,
					DurationSec:  2,
					PayloadBytes: 1100,
					RateMbps:     20,
				},
			})
			if err != nil {
				t.Fatalf("RunClient(%s) failed: %v", dir, err)
			}
			if report.RecvBytes == 0 || report.RecvPackets == 0 {
				t.Fatalf("expected non-zero recv stats, got %+v", report)
			}
			if report.Sender.SentPackets == 0 {
				t.Fatalf("expected non-zero sent packets, got %+v", report.Sender)
			}
			if len(report.Intervals) == 0 {
				t.Fatalf("expected non-empty interval stats")
			}
			t.Log(FormatReport(report))
		})
	}
}

func TestProbeStreamUpload(t *testing.T) {
	addr, _ := startTestServer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	report, err := RunClient(ctx, ClientOptions{
		RemoteAddr:         addr,
		ServerName:         "localhost",
		ALPN:               transport.DefaultALPN,
		InsecureSkipVerify: true,
		Request: Request{
			Proto:       ProtoStream,
			Direction:   DirUpload,
			DurationSec: 2,
		},
	})
	if err != nil {
		t.Fatalf("RunClient(stream) failed: %v", err)
	}
	if report.RecvBytes == 0 || report.RecvMbps <= 0 {
		t.Fatalf("expected positive stream throughput, got %+v", report)
	}
	if len(report.Intervals) == 0 {
		t.Fatalf("expected non-empty interval stats")
	}
	t.Log(FormatReport(report))
}
