package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

const (
	// DefaultALPN disguises QUIC traffic as standard HTTP/3.
	DefaultALPN = "h3"
	// DefaultServerName is used as the default TLS SNI when none is configured.
	DefaultServerName = "www.cloudflare.com"
)

// ServerTLSOptions configures TLS 1.3 for a QUIC listener.
type ServerTLSOptions struct {
	CertFile   string
	KeyFile    string
	ServerName string
	ALPN       string
}

// ClientTLSOptions configures TLS 1.3 for a QUIC dialer.
type ClientTLSOptions struct {
	ServerName         string
	ALPN               string
	CertSHA256         string // pinned hex SHA-256 of leaf certificate DER bytes
	InsecureSkipVerify bool
}

// BuildServerTLSConfig returns a TLS 1.3 server configuration with ALPN set.
// If CertFile and KeyFile are empty, an ephemeral self-signed ECDSA P-256 certificate is generated in memory.
func BuildServerTLSConfig(opts ServerTLSOptions) (*tls.Config, bool, error) {
	alpn := opts.ALPN
	if alpn == "" {
		alpn = DefaultALPN
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = DefaultServerName
	}

	var cert tls.Certificate
	var ephemeral bool
	var err error

	if opts.CertFile != "" || opts.KeyFile != "" {
		if opts.CertFile == "" || opts.KeyFile == "" {
			return nil, false, fmt.Errorf("both cert_file and key_file must be provided together")
		}
		cert, err = tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
		if err != nil {
			return nil, false, fmt.Errorf("load TLS key pair: %w", err)
		}
	} else {
		cert, err = generateSelfSignedCert(serverName, 7*24*time.Hour)
		if err != nil {
			return nil, false, fmt.Errorf("generate ephemeral self-signed cert: %w", err)
		}
		ephemeral = true
	}

	tlsCfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpn},
	}
	return tlsCfg, ephemeral, nil
}

// BuildClientTLSConfig returns a TLS 1.3 client configuration with ALPN, SNI,
// and optional SHA-256 certificate pinning.
func BuildClientTLSConfig(opts ClientTLSOptions) *tls.Config {
	alpn := opts.ALPN
	if alpn == "" {
		alpn = DefaultALPN
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = DefaultServerName
	}

	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}

	pin := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(opts.CertSHA256), ":", ""))
	if pin != "" {
		// Standard CA chain verification is replaced with constant-time leaf cert SHA-256 pinning.
		cfg.InsecureSkipVerify = true
		cfg.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("server presented no TLS certificate")
			}
			sum := sha256.Sum256(rawCerts[0])
			got := hex.EncodeToString(sum[:])
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("TLS certificate SHA-256 pin mismatch: got %s", got)
			}
			return nil
		}
	}

	return cfg
}

// CertSHA256Hex returns the lowercase hex SHA-256 fingerprint of a tls.Certificate leaf.
func CertSHA256Hex(cert tls.Certificate) string {
	if len(cert.Certificate) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return hex.EncodeToString(sum[:])
}

// GenerateCertFiles creates a 10-year ECDSA P-256 self-signed certificate and private key
// PEM pair on disk, returning the leaf certificate's SHA-256 hex fingerprint.
func GenerateCertFiles(certPath, keyPath, serverName string) (string, error) {
	if serverName == "" {
		serverName = DefaultServerName
	}
	cert, err := generateSelfSignedCert(serverName, 10*365*24*time.Hour)
	if err != nil {
		return "", err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Certificate[0],
	})
	keyDER, err := x509.MarshalECPrivateKey(cert.PrivateKey.(*ecdsa.PrivateKey))
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return "", fmt.Errorf("write cert file: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", fmt.Errorf("write key file: %w", err)
	}
	return CertSHA256Hex(cert), nil
}

// GenerateRandomPSK returns a cryptographically random 32-byte hex PSK string.
func GenerateRandomPSK() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func generateSelfSignedCert(serverName string, validFor time.Duration) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(serverName); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else if serverName != "" {
		tmpl.DNSNames = []string{serverName}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}
