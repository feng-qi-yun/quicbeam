package probe

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"runtime"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/feng-qi-yun/quicbeam/internal/transport"
)

const (
	ProtoDatagram = "datagram"
	ProtoStream   = "stream"

	DirUpload   = "upload"
	DirDownload = "download"

	minDatagramPayload = 16
	streamChunkSize    = 32 * 1024
)

// Request is sent by the probe client over the initial control stream.
type Request struct {
	Proto        string  `json:"proto"`
	Direction    string  `json:"direction"`
	DurationSec  int     `json:"duration_sec"`
	PayloadBytes int     `json:"payload_bytes"`
	RateMbps     float64 `json:"rate_mbps"`
}

// Response is sent by the probe server to accept or reject a probe request.
type Response struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// SenderStats is sent by the sender over the control stream when transmission finishes.
type SenderStats struct {
	SentPackets     uint64  `json:"sent_packets"`
	SentBytes       uint64  `json:"sent_bytes"`
	DurationSec     float64 `json:"duration_sec"`
	SendMbps        float64 `json:"send_mbps"`
	EffectiveSize   int     `json:"effective_payload_bytes"`
	MaxDatagramSize int64   `json:"max_datagram_size,omitempty"`
	TooLargeErrors  uint64  `json:"too_large_errors,omitempty"`
}

// IntervalStat holds 1-second receiver-side measurements.
type IntervalStat struct {
	Second      int     `json:"second"`
	Bytes       uint64  `json:"bytes"`
	Mbps        float64 `json:"mbps"`
	Packets     uint64  `json:"packets,omitempty"`
	LostPackets uint64  `json:"lost_packets,omitempty"`
	LossPercent float64 `json:"loss_percent,omitempty"`
	OutOfOrder  uint64  `json:"out_of_order,omitempty"`
}

// Report summarizes a completed probe run.
type Report struct {
	Proto        string         `json:"proto"`
	Direction    string         `json:"direction"`
	DurationSec  float64        `json:"duration_sec"`
	RecvBytes    uint64         `json:"recv_bytes"`
	RecvMbps     float64        `json:"recv_mbps"`
	RecvPackets  uint64         `json:"recv_packets,omitempty"`
	OutOfOrder   uint64         `json:"out_of_order,omitempty"`
	Sender       SenderStats    `json:"sender"`
	TotalLossPct float64        `json:"total_loss_pct,omitempty"`
	Intervals    []IntervalStat `json:"intervals"`
}

// ServerOptions configures the probe server.
type ServerOptions struct {
	ListenAddr string
	ServerName string
	ALPN       string
	CertFile   string
	KeyFile    string
}

// ClientOptions configures a probe client run.
type ClientOptions struct {
	RemoteAddr         string
	ServerName         string
	ALPN               string
	InsecureSkipVerify bool
	Request            Request
}

// Validate checks and fills default values on a Request.
func (r *Request) Validate() error {
	if r.Proto == "" {
		r.Proto = ProtoDatagram
	}
	if r.Proto != ProtoDatagram && r.Proto != ProtoStream {
		return fmt.Errorf("invalid proto %q (must be %q or %q)", r.Proto, ProtoDatagram, ProtoStream)
	}
	if r.Direction == "" {
		r.Direction = DirUpload
	}
	if r.Direction != DirUpload && r.Direction != DirDownload {
		return fmt.Errorf("invalid direction %q (must be %q or %q)", r.Direction, DirUpload, DirDownload)
	}
	if r.DurationSec <= 0 {
		r.DurationSec = 15
	}
	if r.DurationSec > 300 {
		return fmt.Errorf("duration_sec %d exceeds maximum 300", r.DurationSec)
	}
	if r.Proto == ProtoDatagram {
		if r.PayloadBytes == 0 {
			r.PayloadBytes = 1150
		}
		if r.PayloadBytes < minDatagramPayload || r.PayloadBytes > 65507 {
			return fmt.Errorf("payload_bytes %d out of range [%d, 65507]", r.PayloadBytes, minDatagramPayload)
		}
		if r.RateMbps < 0 {
			return fmt.Errorf("rate_mbps must be >= 0")
		}
	}
	return nil
}

// RunServer starts a QUIC probe server and handles incoming probe sessions until ctx is canceled.
func RunServer(ctx context.Context, opts ServerOptions) error {
	tlsCfg, ephemeral, err := transport.BuildServerTLSConfig(transport.ServerTLSOptions{
		CertFile:   opts.CertFile,
		KeyFile:    opts.KeyFile,
		ServerName: opts.ServerName,
		ALPN:       opts.ALPN,
	})
	if err != nil {
		return err
	}
	if ephemeral {
		slog.Info("probe server using ephemeral self-signed TLS 1.3 cert",
			"sni", opts.ServerName,
			"alpn", tlsCfg.NextProtos,
		)
	}

	ln, err := transport.Listen(opts.ListenAddr, tlsCfg, transport.DefaultQUICConfig())
	if err != nil {
		return err
	}
	defer ln.Close()

	return ServeListener(ctx, ln)
}

// ServeListener accepts QUIC connections on ln and serves probe sessions until ctx is canceled.
func ServeListener(ctx context.Context, ln *quic.Listener) error {
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
			defer c.CloseWithError(0, "probe session complete")
			if err := handleServerConn(ctx, c); err != nil {
				slog.Warn("probe session ended with error", "remote", c.RemoteAddr().String(), "err", err)
			}
		}(conn)
	}
}

func handleServerConn(ctx context.Context, conn *quic.Conn) error {
	state := conn.ConnectionState()
	slog.Info("probe client connected",
		"remote", conn.RemoteAddr().String(),
		"alpn", state.TLS.NegotiatedProtocol,
		"remote_datagrams", state.SupportsDatagrams.Remote,
	)

	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return fmt.Errorf("accept control stream: %w", err)
	}
	defer ctrl.Close()

	dec := json.NewDecoder(ctrl)
	enc := json.NewEncoder(ctrl)

	var req Request
	if err := dec.Decode(&req); err != nil {
		return fmt.Errorf("decode probe request: %w", err)
	}
	if err := req.Validate(); err != nil {
		_ = enc.Encode(Response{OK: false, Error: err.Error()})
		return err
	}
	if req.Proto == ProtoDatagram && !state.SupportsDatagrams.Remote {
		msg := "peer does not support RFC 9221 QUIC Datagrams"
		_ = enc.Encode(Response{OK: false, Error: msg})
		return errors.New(msg)
	}
	if err := enc.Encode(Response{OK: true}); err != nil {
		return fmt.Errorf("encode probe response: %w", err)
	}

	slog.Info("starting probe session",
		"remote", conn.RemoteAddr().String(),
		"proto", req.Proto,
		"direction", req.Direction,
		"duration_sec", req.DurationSec,
		"payload_bytes", req.PayloadBytes,
		"rate_mbps", req.RateMbps,
	)

	var report *Report
	switch req.Direction {
	case DirUpload:
		// Client sends, server receives.
		report, err = runReceiver(ctx, conn, req, dec, enc)
	case DirDownload:
		// Server sends, client receives.
		report, err = runSender(ctx, conn, req, dec, enc)
	}
	if err != nil {
		return err
	}

	slog.Info("probe session finished",
		"remote", conn.RemoteAddr().String(),
		"proto", report.Proto,
		"direction", report.Direction,
		"recv_mbps", fmt.Sprintf("%.2f", report.RecvMbps),
		"send_mbps", fmt.Sprintf("%.2f", report.Sender.SendMbps),
		"loss_pct", fmt.Sprintf("%.2f", report.TotalLossPct),
	)

	// Allow the client to read the final report and close the connection first,
	// avoiding CONNECTION_CLOSE truncating in-flight control stream data.
	_ = ctrl.Close()
	select {
	case <-conn.Context().Done():
	case <-time.After(2 * time.Second):
	case <-ctx.Done():
	}
	return nil
}

// RunClient connects to a probe server, executes the requested probe, and returns the Report.
func RunClient(ctx context.Context, opts ClientOptions) (*Report, error) {
	req := opts.Request
	if err := req.Validate(); err != nil {
		return nil, err
	}

	tlsCfg := transport.BuildClientTLSConfig(transport.ClientTLSOptions{
		ServerName:         opts.ServerName,
		ALPN:               opts.ALPN,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	})

	conn, err := transport.Dial(ctx, opts.RemoteAddr, tlsCfg, transport.DefaultQUICConfig())
	if err != nil {
		return nil, err
	}
	defer conn.CloseWithError(0, "probe client done")

	if req.Proto == ProtoDatagram && !conn.ConnectionState().SupportsDatagrams.Remote {
		return nil, errors.New("server does not support RFC 9221 QUIC Datagrams")
	}

	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open control stream: %w", err)
	}
	defer ctrl.Close()

	enc := json.NewEncoder(ctrl)
	dec := json.NewDecoder(ctrl)

	if err := enc.Encode(req); err != nil {
		return nil, fmt.Errorf("encode probe request: %w", err)
	}

	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("decode probe response: %w", err)
	}
	if !resp.OK {
		return nil, fmt.Errorf("server rejected probe: %s", resp.Error)
	}

	switch req.Direction {
	case DirUpload:
		return runSender(ctx, conn, req, dec, enc)
	case DirDownload:
		return runReceiver(ctx, conn, req, dec, enc)
	default:
		return nil, fmt.Errorf("unsupported direction: %s", req.Direction)
	}
}

func runSender(ctx context.Context, conn *quic.Conn, req Request, dec *json.Decoder, enc *json.Encoder) (*Report, error) {
	var senderStats SenderStats
	var err error

	switch req.Proto {
	case ProtoDatagram:
		senderStats, err = sendDatagrams(ctx, conn, req)
	case ProtoStream:
		senderStats, err = sendStream(ctx, conn, req)
	}
	if err != nil {
		return nil, err
	}

	if err := enc.Encode(senderStats); err != nil {
		return nil, fmt.Errorf("send sender stats: %w", err)
	}

	var report Report
	if err := dec.Decode(&report); err != nil {
		return nil, fmt.Errorf("receive probe report: %w", err)
	}
	return &report, nil
}

func runReceiver(ctx context.Context, conn *quic.Conn, req Request, dec *json.Decoder, enc *json.Encoder) (*Report, error) {
	var report *Report
	var err error

	switch req.Proto {
	case ProtoDatagram:
		report, err = recvDatagrams(ctx, conn, req, dec)
	case ProtoStream:
		report, err = recvStream(ctx, conn, req, dec)
	}
	if err != nil {
		return nil, err
	}

	if err := enc.Encode(report); err != nil {
		return nil, fmt.Errorf("send probe report: %w", err)
	}
	return report, nil
}

func sendDatagrams(ctx context.Context, conn *quic.Conn, req Request) (SenderStats, error) {
	payloadSize := req.PayloadBytes
	buf := make([]byte, payloadSize)
	for i := minDatagramPayload; i < len(buf); i++ {
		buf[i] = byte(i)
	}

	duration := time.Duration(req.DurationSec) * time.Second
	start := time.Now()
	deadline := start.Add(duration)

	var (
		seq            uint64
		sentBytes      uint64
		tooLargeErrors uint64
		maxDgramSize   int64
	)

	for {
		now := time.Now()
		if !now.Before(deadline) || ctx.Err() != nil {
			break
		}

		// Token-bucket batch pacing: resilient to coarse OS timers on Windows.
		if req.RateMbps > 0 {
			elapsed := now.Sub(start).Seconds()
			if elapsed < 0 {
				elapsed = 0
			}
			// Allow a small initial burst (1ms worth of packets, at least 1).
			targetPkts := uint64((elapsed+0.001)*(req.RateMbps*1e6)/float64(payloadSize*8)) + 1
			if seq >= targetPkts {
				time.Sleep(1 * time.Millisecond)
				continue
			}
		}

		seq++
		binary.BigEndian.PutUint64(buf[0:8], seq)
		binary.BigEndian.PutUint64(buf[8:16], uint64(now.UnixNano()))

		err := conn.SendDatagram(buf[:payloadSize])
		if err != nil {
			var tooLarge *quic.DatagramTooLargeError
			if errors.As(err, &tooLarge) {
				tooLargeErrors++
				maxDgramSize = tooLarge.MaxDatagramPayloadSize
				slog.Warn("QUIC datagram exceeded path MaxDatagramSize, shrinking payload",
					"requested_bytes", payloadSize,
					"max_datagram_size", tooLarge.MaxDatagramPayloadSize,
				)
				if tooLarge.MaxDatagramPayloadSize < minDatagramPayload {
					return SenderStats{}, fmt.Errorf("max datagram payload size too small: %d", tooLarge.MaxDatagramPayloadSize)
				}
				payloadSize = int(tooLarge.MaxDatagramPayloadSize)
				seq-- // retry with shrunk payload
				continue
			}
			if ctx.Err() != nil {
				break
			}
			return SenderStats{}, fmt.Errorf("send datagram: %w", err)
		}
		sentBytes += uint64(payloadSize)

		// Yield occasionally when unpaced to avoid starving QUIC's internal loops.
		if req.RateMbps == 0 && seq%256 == 0 {
			runtime.Gosched()
		}
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}

	return SenderStats{
		SentPackets:     seq,
		SentBytes:       sentBytes,
		DurationSec:     elapsed,
		SendMbps:        float64(sentBytes*8) / (elapsed * 1e6),
		EffectiveSize:   payloadSize,
		MaxDatagramSize: maxDgramSize,
		TooLargeErrors:  tooLargeErrors,
	}, nil
}

func recvDatagrams(ctx context.Context, conn *quic.Conn, req Request, dec *json.Decoder) (*Report, error) {
	recvCtx, cancelRecv := context.WithCancel(ctx)
	defer cancelRecv()

	var (
		mu          sync.Mutex
		started     bool
		startTime   time.Time
		totalBytes  uint64
		totalPkts   uint64
		highestSeq  uint64
		outOfOrder  uint64
		intervals   []IntervalStat
		curSec      = 1
		curBytes    uint64
		curPkts     uint64
		curOOO      uint64
		curStartSeq uint64
	)

	flushInterval := func(sec int) {
		var lost uint64
		var lossPct float64
		if highestSeq > curStartSeq {
			expected := highestSeq - curStartSeq
			if expected > curPkts {
				lost = expected - curPkts
			}
			if expected > 0 {
				lossPct = float64(lost) / float64(expected) * 100
			}
		}
		intervals = append(intervals, IntervalStat{
			Second:      sec,
			Bytes:       curBytes,
			Mbps:        float64(curBytes*8) / 1e6,
			Packets:     curPkts,
			LostPackets: lost,
			LossPercent: lossPct,
			OutOfOrder:  curOOO,
		})
		curBytes = 0
		curPkts = 0
		curOOO = 0
		curStartSeq = highestSeq
	}

	recvDone := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		// Separate goroutine to tick 1-second buckets while receiving datagrams.
		tickDone := make(chan struct{})
		go func() {
			defer close(tickDone)
			for {
				select {
				case <-recvCtx.Done():
					return
				case <-ticker.C:
					mu.Lock()
					if started {
						flushInterval(curSec)
						curSec++
					}
					mu.Unlock()
				}
			}
		}()

		for {
			pkt, err := conn.ReceiveDatagram(recvCtx)
			if err != nil {
				<-tickDone
				if recvCtx.Err() != nil {
					recvDone <- nil
					return
				}
				recvDone <- err
				return
			}
			if len(pkt) < minDatagramPayload {
				continue
			}
			seq := binary.BigEndian.Uint64(pkt[0:8])
			n := uint64(len(pkt))

			mu.Lock()
			if !started {
				started = true
				startTime = time.Now()
			}
			totalBytes += n
			totalPkts++
			curBytes += n
			curPkts++
			if seq > highestSeq {
				highestSeq = seq
			} else {
				outOfOrder++
				curOOO++
			}
			mu.Unlock()
		}
	}()

	// Wait for sender to signal completion on the control stream.
	var senderStats SenderStats
	if err := dec.Decode(&senderStats); err != nil {
		cancelRecv()
		<-recvDone
		return nil, fmt.Errorf("decode sender stats: %w", err)
	}

	// Brief drain window for in-flight datagrams.
	select {
	case <-time.After(250 * time.Millisecond):
	case <-ctx.Done():
	}
	cancelRecv()
	if err := <-recvDone; err != nil {
		return nil, fmt.Errorf("receive datagrams: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()

	// Flush any partial final interval if significant packets arrived in it.
	if curPkts > 0 && len(intervals) < req.DurationSec {
		flushInterval(curSec)
	}

	elapsed := senderStats.DurationSec
	if elapsed <= 0 && started {
		elapsed = time.Since(startTime).Seconds()
	}
	if elapsed <= 0 {
		elapsed = float64(req.DurationSec)
	}

	var totalLossPct float64
	if senderStats.SentPackets > 0 && senderStats.SentPackets >= totalPkts {
		totalLossPct = float64(senderStats.SentPackets-totalPkts) / float64(senderStats.SentPackets) * 100
	}

	return &Report{
		Proto:        req.Proto,
		Direction:    req.Direction,
		DurationSec:  elapsed,
		RecvBytes:    totalBytes,
		RecvMbps:     float64(totalBytes*8) / (elapsed * 1e6),
		RecvPackets:  totalPkts,
		OutOfOrder:   outOfOrder,
		Sender:       senderStats,
		TotalLossPct: math.Max(0, totalLossPct),
		Intervals:    intervals,
	}, nil
}

func sendStream(ctx context.Context, conn *quic.Conn, req Request) (SenderStats, error) {
	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		return SenderStats{}, fmt.Errorf("open uni stream: %w", err)
	}

	buf := make([]byte, streamChunkSize)
	for i := range buf {
		buf[i] = byte(i)
	}

	duration := time.Duration(req.DurationSec) * time.Second
	start := time.Now()
	deadline := start.Add(duration)
	_ = stream.SetWriteDeadline(deadline)

	var sentBytes uint64
	for time.Now().Before(deadline) && ctx.Err() == nil {
		n, err := stream.Write(buf)
		sentBytes += uint64(n)
		if err != nil {
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				break
			}
			if ctx.Err() != nil {
				break
			}
			_ = stream.Close()
			return SenderStats{}, fmt.Errorf("write stream: %w", err)
		}
	}

	_ = stream.SetWriteDeadline(time.Time{})
	if err := stream.Close(); err != nil {
		return SenderStats{}, fmt.Errorf("close uni stream: %w", err)
	}

	elapsed := time.Since(start).Seconds()
	if elapsed <= 0 {
		elapsed = 0.001
	}

	return SenderStats{
		SentBytes:     sentBytes,
		DurationSec:   elapsed,
		SendMbps:      float64(sentBytes*8) / (elapsed * 1e6),
		EffectiveSize: streamChunkSize,
	}, nil
}

func recvStream(ctx context.Context, conn *quic.Conn, req Request, dec *json.Decoder) (*Report, error) {
	stream, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("accept uni stream: %w", err)
	}

	var (
		mu         sync.Mutex
		startTime  = time.Now()
		totalBytes uint64
		curBytes   uint64
		curSec     = 1
		intervals  []IntervalStat
	)

	tickCtx, cancelTick := context.WithCancel(ctx)
	tickDone := make(chan struct{})
	go func() {
		defer close(tickDone)
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-tickCtx.Done():
				return
			case <-ticker.C:
				mu.Lock()
				intervals = append(intervals, IntervalStat{
					Second: curSec,
					Bytes:  curBytes,
					Mbps:   float64(curBytes*8) / 1e6,
				})
				curBytes = 0
				curSec++
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, streamChunkSize)
	for {
		n, readErr := stream.Read(buf)
		if n > 0 {
			mu.Lock()
			totalBytes += uint64(n)
			curBytes += uint64(n)
			mu.Unlock()
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			cancelTick()
			<-tickDone
			return nil, fmt.Errorf("read uni stream: %w", readErr)
		}
	}

	cancelTick()
	<-tickDone
	recvElapsed := time.Since(startTime).Seconds()

	var senderStats SenderStats
	if err := dec.Decode(&senderStats); err != nil {
		return nil, fmt.Errorf("decode stream sender stats: %w", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if curBytes > 0 && len(intervals) < req.DurationSec {
		intervals = append(intervals, IntervalStat{
			Second: curSec,
			Bytes:  curBytes,
			Mbps:   float64(curBytes*8) / 1e6,
		})
	}

	elapsed := recvElapsed
	if elapsed <= 0 {
		elapsed = senderStats.DurationSec
	}
	if elapsed <= 0 {
		elapsed = float64(req.DurationSec)
	}

	return &Report{
		Proto:       req.Proto,
		Direction:   req.Direction,
		DurationSec: elapsed,
		RecvBytes:   totalBytes,
		RecvMbps:    float64(totalBytes*8) / (elapsed * 1e6),
		Sender:      senderStats,
		Intervals:   intervals,
	}, nil
}

// FormatReport renders a human-readable per-second table and summary for terminal output.
func FormatReport(r *Report) string {
	out := fmt.Sprintf("\n=== QuicBeam Probe Report (%s / %s) ===\n", r.Proto, r.Direction)
	if r.Proto == ProtoDatagram {
		out += fmt.Sprintf("%-6s | %-12s | %-10s | %-10s | %-8s | %-6s\n",
			"Sec", "Recv (Mbps)", "Recv Pkts", "Lost Pkts", "Loss (%)", "OOO")
		out += "-------+--------------+------------+------------+----------+-------\n"
		for _, iv := range r.Intervals {
			out += fmt.Sprintf("%-6d | %12.2f | %10d | %10d | %8.2f | %6d\n",
				iv.Second, iv.Mbps, iv.Packets, iv.LostPackets, iv.LossPercent, iv.OutOfOrder)
		}
		out += fmt.Sprintf("\nSummary: duration=%.2fs, send=%.2f Mbps (%d pkts, payload=%dB), recv=%.2f Mbps (%d pkts), loss=%.2f%%, ooo=%d\n",
			r.DurationSec, r.Sender.SendMbps, r.Sender.SentPackets, r.Sender.EffectiveSize,
			r.RecvMbps, r.RecvPackets, r.TotalLossPct, r.OutOfOrder)
		if r.Sender.TooLargeErrors > 0 {
			out += fmt.Sprintf("WARNING: %d DatagramTooLargeError(s) observed; path MaxDatagramSize=%d bytes\n",
				r.Sender.TooLargeErrors, r.Sender.MaxDatagramSize)
		}
	} else {
		out += fmt.Sprintf("%-6s | %-12s | %-12s\n", "Sec", "Recv (Mbps)", "Recv Bytes")
		out += "-------+--------------+-------------\n"
		for _, iv := range r.Intervals {
			out += fmt.Sprintf("%-6d | %12.2f | %12d\n", iv.Second, iv.Mbps, iv.Bytes)
		}
		out += fmt.Sprintf("\nSummary: duration=%.2fs, send=%.2f Mbps (%d bytes), recv=%.2f Mbps (%d bytes)\n",
			r.DurationSec, r.Sender.SendMbps, r.Sender.SentBytes, r.RecvMbps, r.RecvBytes)
	}
	return out
}
