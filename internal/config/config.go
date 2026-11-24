package config

// PortForward defines a single TCP or UDP port forwarding mapping over the QUIC tunnel.
type PortForward struct {
	Name   string `json:"name"`
	Proto  string `json:"proto"`  // "tcp" (QUIC Stream) or "udp" (QUIC Datagram)
	Listen string `json:"listen"` // local bind address, e.g. "127.0.0.1:47998"
	Target string `json:"target"` // remote target address, e.g. "127.0.0.1:47998"
}

// Config holds the runtime configuration for quicbeam server or client.
type Config struct {
	Role       string        `json:"role"`        // "server" or "client"
	ListenAddr string        `json:"listen_addr"` // e.g. ":443"
	RemoteAddr string        `json:"remote_addr"` // peer address for client mode
	ServerName string        `json:"server_name"` // TLS SNI
	ALPN       string        `json:"alpn"`        // default "h3"
	CertFile   string        `json:"cert_file"`
	KeyFile    string        `json:"key_file"`
	PSK        string        `json:"psk"`
	Forwards   []PortForward `json:"forwards"`
}
