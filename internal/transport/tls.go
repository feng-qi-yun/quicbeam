package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
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
		cert, err = generateSelfSignedCert(serverName)
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

// BuildClientTLSConfig returns a TLS 1.3 client configuration with ALPN and SNI set.
func BuildClientTLSConfig(opts ClientTLSOptions) *tls.Config {
	alpn := opts.ALPN
	if alpn == "" {
		alpn = DefaultALPN
	}
	serverName := opts.ServerName
	if serverName == "" {
		serverName = DefaultServerName
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		NextProtos:         []string{alpn},
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}
}

func generateSelfSignedCert(serverName string) (tls.Certificate, error) {
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
		NotAfter:              now.Add(7 * 24 * time.Hour),
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
