package forward

import (
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	streamTypeTCP byte = 0x01

	streamStatusOK  byte = 0x00
	streamStatusErr byte = 0x01

	maxTargetLen = 512
)

// UDPChannelSpec describes a multiplexed UDP forwarding channel negotiated at handshake.
type UDPChannelSpec struct {
	ID     uint8  `json:"id"`
	Name   string `json:"name"`
	Target string `json:"target"`
}

// AuthRequest is sent by the QUIC client on the first bidirectional stream.
type AuthRequest struct {
	PSK         string           `json:"psk"`
	UDPChannels []UDPChannelSpec `json:"udp_channels,omitempty"`
}

// AuthResponse is returned by the QUIC server on the first bidirectional stream.
type AuthResponse struct {
	OK          bool             `json:"ok"`
	Error       string           `json:"error,omitempty"`
	UDPChannels []UDPChannelSpec `json:"udp_channels,omitempty"`
}

// ConstantTimePSKMatch compares two PSKs without timing side-channels.
func ConstantTimePSKMatch(a, b string) bool {
	if len(a) == 0 || len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func writeJSON(w io.Writer, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func readJSON(r io.Reader, v any) error {
	return json.NewDecoder(r).Decode(v)
}

func writeTCPStreamHeader(w io.Writer, target string) error {
	if len(target) == 0 || len(target) > maxTargetLen {
		return fmt.Errorf("invalid target length: %d", len(target))
	}
	hdr := make([]byte, 3+len(target))
	hdr[0] = streamTypeTCP
	binary.BigEndian.PutUint16(hdr[1:3], uint16(len(target)))
	copy(hdr[3:], target)
	_, err := w.Write(hdr)
	return err
}

func readTCPStreamHeader(r io.Reader) (string, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != streamTypeTCP {
		return "", fmt.Errorf("unexpected stream type: 0x%02x", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[1:3]))
	if n == 0 || n > maxTargetLen {
		return "", fmt.Errorf("invalid target length: %d", n)
	}
	targetBuf := make([]byte, n)
	if _, err := io.ReadFull(r, targetBuf); err != nil {
		return "", err
	}
	return string(targetBuf), nil
}

func writeStreamStatus(w io.Writer, ok bool) error {
	b := streamStatusErr
	if ok {
		b = streamStatusOK
	}
	_, err := w.Write([]byte{b})
	return err
}

func readStreamStatus(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	if b[0] != streamStatusOK {
		return errors.New("peer failed to dial target")
	}
	return nil
}
