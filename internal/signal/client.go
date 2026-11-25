package signal

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/feng-qi-yun/quicbeam/internal/config"
)

// PeerEndpoint represents a peer's publicly reachable addresses encrypted in transit.
type PeerEndpoint struct {
	Role      string    `json:"role"`
	IPv4      string    `json:"ipv4,omitempty"`
	Port      int       `json:"port"`
	IPv6      []string  `json:"ipv6,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CandidateAddrs returns ordered host:port dial candidates according to preferIPv6.
func (e *PeerEndpoint) CandidateAddrs(preferIPv6 bool) []string {
	if e == nil || e.Port <= 0 {
		return nil
	}
	portStr := strconv.Itoa(e.Port)
	var v4 []string
	if e.IPv4 != "" {
		v4 = append(v4, net.JoinHostPort(e.IPv4, portStr))
	}
	var v6 []string
	for _, ip := range e.IPv6 {
		if ip != "" {
			v6 = append(v6, net.JoinHostPort(ip, portStr))
		}
	}
	if preferIPv6 {
		return append(v6, v4...)
	}
	return append(v4, v6...)
}

// Client exchanges AES-256-GCM encrypted PeerEndpoints with a lightweight HTTP KV service.
type Client struct {
	baseURL    string
	room       string
	token      string
	psk        string
	httpClient *http.Client
}

// NewClient creates a signaling client from SignalConfig and the tunnel PSK.
func NewClient(cfg *config.SignalConfig, psk string) *Client {
	return &Client{
		baseURL: strings.TrimRight(cfg.URL, "/"),
		room:    cfg.Room,
		token:   cfg.Token,
		psk:     psk,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (c *Client) endpointURL(role string) string {
	return fmt.Sprintf("%s/%s/%s", c.baseURL, url.PathEscape(c.room), url.PathEscape(role))
}

// Publish encrypts ep with AES-256-GCM (derived from PSK) and PUTs it to the signaling store.
func (c *Client) Publish(ctx context.Context, ep *PeerEndpoint) error {
	cipherText, err := EncryptEndpoint(c.psk, ep)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpointURL(ep.Role), bytes.NewBufferString(cipherText))
	if err != nil {
		return fmt.Errorf("create signal PUT request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("signal PUT failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("signal PUT status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// FetchPeer retrieves and decrypts the peer's latest PeerEndpoint from the signaling store.
func (c *Client) FetchPeer(ctx context.Context, peerRole string) (*PeerEndpoint, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpointURL(peerRole), nil)
	if err != nil {
		return nil, fmt.Errorf("create signal GET request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("signal GET failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("signal GET status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if err != nil {
		return nil, fmt.Errorf("read signal body: %w", err)
	}
	return DecryptEndpoint(c.psk, strings.TrimSpace(string(raw)))
}

// EncryptEndpoint serializes and encrypts ep using AES-256-GCM with key = SHA-256(psk).
func EncryptEndpoint(psk string, ep *PeerEndpoint) (string, error) {
	if psk == "" {
		return "", errors.New("psk must not be empty")
	}
	plain, err := json.Marshal(ep)
	if err != nil {
		return "", fmt.Errorf("marshal endpoint: %w", err)
	}

	key := sha256.Sum256([]byte(psk))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plain, nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

// DecryptEndpoint decodes and authenticates a ciphertext produced by EncryptEndpoint.
func DecryptEndpoint(psk, encoded string) (*PeerEndpoint, error) {
	if psk == "" {
		return nil, errors.New("psk must not be empty")
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signal base64: %w", err)
	}

	key := sha256.Sum256([]byte(psk))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("signal ciphertext too short")
	}

	nonce := raw[:gcm.NonceSize()]
	cipherText := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt signal endpoint (wrong PSK or tampered data): %w", err)
	}

	var ep PeerEndpoint
	if err := json.Unmarshal(plain, &ep); err != nil {
		return nil, fmt.Errorf("unmarshal endpoint: %w", err)
	}
	return &ep, nil
}
