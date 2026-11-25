package forward

import (
	"encoding/binary"
	"sync"
	"time"
)

const (
	// fragEscapeByte marks a fragmented UDP datagram carrying a 6-byte header:
	// [0xFF][1B channel_id][2B msg_id][1B frag_idx][1B frag_total][chunk]
	fragEscapeByte byte = 0xFF
	fragHeaderSize      = 6
	maxFragCount        = 16
	reassemblyTTL       = 150 * time.Millisecond
	maxReassemblySlots  = 128
)

type reassemblyKey struct {
	channelID uint8
	msgID     uint16
}

type reassemblyEntry struct {
	createdAt time.Time
	total     uint8
	received  uint8
	chunks    [][]byte
	totalLen  int
}

// datagramReassembler reassembles fragmented unreliable UDP datagrams without
// head-of-line blocking; incomplete packets are evicted after reassemblyTTL.
type datagramReassembler struct {
	mu      sync.Mutex
	entries map[reassemblyKey]*reassemblyEntry
}

func newDatagramReassembler() *datagramReassembler {
	return &datagramReassembler{
		entries: make(map[reassemblyKey]*reassemblyEntry, 32),
	}
}

// push adds a fragment payload (starting at fragEscapeByte) and returns
// (channelID, fullPayload, true) once all fragments for that message arrive.
func (r *datagramReassembler) push(pkt []byte) (uint8, []byte, bool) {
	if len(pkt) <= fragHeaderSize || pkt[0] != fragEscapeByte {
		return 0, nil, false
	}
	channelID := pkt[1]
	msgID := binary.BigEndian.Uint16(pkt[2:4])
	fragIdx := pkt[4]
	fragTotal := pkt[5]
	chunk := pkt[fragHeaderSize:]

	if fragTotal < 2 || fragTotal > maxFragCount || fragIdx >= fragTotal {
		return 0, nil, false
	}

	now := time.Now()
	key := reassemblyKey{channelID: channelID, msgID: msgID}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Evict stale entries when table grows.
	if len(r.entries) >= maxReassemblySlots {
		for k, e := range r.entries {
			if now.Sub(e.createdAt) > reassemblyTTL {
				delete(r.entries, k)
			}
		}
		// If still full, clear oldest-style by dropping map to keep memory bounded.
		if len(r.entries) >= maxReassemblySlots {
			clear(r.entries)
		}
	}

	entry, ok := r.entries[key]
	if !ok || now.Sub(entry.createdAt) > reassemblyTTL || entry.total != fragTotal {
		entry = &reassemblyEntry{
			createdAt: now,
			total:     fragTotal,
			chunks:    make([][]byte, fragTotal),
		}
		r.entries[key] = entry
	}

	if entry.chunks[fragIdx] == nil {
		cp := make([]byte, len(chunk))
		copy(cp, chunk)
		entry.chunks[fragIdx] = cp
		entry.received++
		entry.totalLen += len(cp)
	}

	if entry.received < entry.total {
		return 0, nil, false
	}

	delete(r.entries, key)
	out := make([]byte, 0, entry.totalLen)
	for _, c := range entry.chunks {
		out = append(out, c...)
	}
	return channelID, out, true
}

// buildFragments splits payload for channelID into QUIC datagrams each <= maxDatagramSize.
func buildFragments(channelID uint8, msgID uint16, payload []byte, maxDatagramSize int) [][]byte {
	maxChunk := maxDatagramSize - fragHeaderSize
	if maxChunk <= 0 {
		return nil
	}
	total := (len(payload) + maxChunk - 1) / maxChunk
	if total < 2 || total > maxFragCount {
		return nil
	}

	frags := make([][]byte, 0, total)
	for idx := 0; idx < total; idx++ {
		start := idx * maxChunk
		end := start + maxChunk
		if end > len(payload) {
			end = len(payload)
		}
		chunk := payload[start:end]
		pkt := make([]byte, fragHeaderSize+len(chunk))
		pkt[0] = fragEscapeByte
		pkt[1] = channelID
		binary.BigEndian.PutUint16(pkt[2:4], msgID)
		pkt[4] = uint8(idx)
		pkt[5] = uint8(total)
		copy(pkt[fragHeaderSize:], chunk)
		frags = append(frags, pkt)
	}
	return frags
}
