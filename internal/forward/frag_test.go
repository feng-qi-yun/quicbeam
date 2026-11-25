package forward

import (
	"bytes"
	"testing"
)

func TestDatagramFragmentAndReassemble(t *testing.T) {
	payload := bytes.Repeat([]byte("MoonlightVideoPacket1408"), 60) // 1440 bytes
	frags := buildFragments(128, 42, payload, 1200)
	if len(frags) != 2 {
		t.Fatalf("expected 2 fragments, got %d", len(frags))
	}
	for i, f := range frags {
		if len(f) > 1200 {
			t.Fatalf("fragment %d exceeds max size: %d", i, len(f))
		}
	}

	r := newDatagramReassembler()
	// Deliver out-of-order (frag 1 before frag 0) to verify order independence.
	if _, _, ok := r.push(frags[1]); ok {
		t.Fatalf("should not complete after only 1 fragment")
	}
	chID, got, ok := r.push(frags[0])
	if !ok {
		t.Fatalf("expected reassembly to complete after 2nd fragment")
	}
	if chID != 128 {
		t.Fatalf("expected channelID 128, got %d", chID)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("reassembled payload mismatch: got %d bytes, want %d", len(got), len(payload))
	}
}
