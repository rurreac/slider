package conf

import "time"

const (
	// Ticker intervals for command status polling

	// ConnectTickerInterval is the polling interval for connection establishment
	ConnectTickerInterval = 500 * time.Millisecond

	// EndpointTickerInterval is the polling interval for endpoint startup (ssh, socks, shell, portfwd)
	EndpointTickerInterval = 250 * time.Millisecond

	// File size constants for display formatting

	BytesPerKB = 1024
	BytesPerMB = 1024 * 1024
	BytesPerGB = 1024 * 1024 * 1024

	// Buffer sizes

	// SFTPBufferSize is the buffer size for SFTP file transfers (32KB)
	SFTPBufferSize = 32 * 1024

	// DefaultHistorySize is the default maximum size for command history
	DefaultHistorySize = 100

	// Progress display constants

	// ProgressBarWidth is the width of progress bars in characters
	ProgressBarWidth = 50

	// PercentageMultiplier for converting to percentage
	PercentageMultiplier = 100.0
)
