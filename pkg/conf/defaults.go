package conf

import "time"

const (
	// Timeout acts as the general Timeout default value
	Timeout = 10 * time.Second

	// dnsTimeout is the resolver timeout default value
	dnsTimeout = 5 * time.Second

	// Keepalive acts as the general KeepAlive default value
	Keepalive = 60 * time.Second

	// MinKeepAlive is the minimum keepalive allowed duration
	MinKeepAlive = 5 * time.Second

	// ConnectTickerInterval is the polling interval for connection establishments
	ConnectTickerInterval = 500 * time.Millisecond

	// EndpointTickerInterval is the polling interval for endpoint startup (ssh, socks, shell, portfwd)
	EndpointTickerInterval = 250 * time.Millisecond

	// File size constants for display formatting

	BytesPerKB = 1024
	BytesPerMB = 1024 * 1024
	BytesPerGB = 1024 * 1024 * 1024

	// SFTPBufferSize is the buffer size for SFTP file transfers (32KB)
	SFTPBufferSize = 32 * 1024

	// DefaultHistorySize is the default maximum size for command history
	DefaultHistorySize = 100

	// Terminal size

	DefaultTerminalWidth  = 80
	DefaultTerminalHeight = 24

	// MaxUDPPacketSize is the maximum size of a UDP packet
	MaxUDPPacketSize = 65535
)
