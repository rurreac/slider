package socks

import (
	"fmt"
	"net"
	"slider/pkg/slog"

	"github.com/armon/go-socks5"
)

// NewServer creates a configured SOCKS5 server instance with logging disabled
func NewServer() (*socks5.Server, error) {
	conf := &socks5.Config{
		Logger: slog.NewDummyLog(),
	}
	return socks5.New(conf)
}

// LocalServer manages a standalone local SOCKS5 server
type LocalServer struct {
	listener net.Listener
	port     int
	stopChan chan struct{}
	server   *socks5.Server
	logger   *slog.Logger
}

// NewLocalServer creates and starts a new local SOCKS5 server
func NewLocalServer(port int, expose bool, logger *slog.Logger) (*LocalServer, error) {
	// Determine bind address
	addr := "127.0.0.1"
	if expose {
		addr = "0.0.0.0"
	}

	// Create SOCKS5 server
	server, err := NewServer()
	if err != nil {
		return nil, fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}

	// Create TCP listener
	listener, lErr := net.Listen("tcp", fmt.Sprintf("%s:%d", addr, port))
	if lErr != nil {
		return nil, fmt.Errorf("failed to create listener: %w", lErr)
	}

	// Get actual port if random was requested
	if port == 0 {
		port = listener.Addr().(*net.TCPAddr).Port
	}

	return &LocalServer{
		listener: listener,
		port:     port,
		stopChan: make(chan struct{}),
		server:   server,
		logger:   logger,
	}, nil
}

// Port returns the port the server is listening on
func (ls *LocalServer) Port() int {
	return ls.port
}

// Start begins accepting and serving SOCKS5 connections
// This method blocks until the server is stopped
func (ls *LocalServer) Start() {
	defer func() {
		_ = ls.listener.Close()
		ls.logger.InfoWith("Local SOCKS server stopped")
	}()

	ls.logger.InfoWith("Local SOCKS server listening", slog.F("port", ls.port))

	// Accept connections and serve SOCKS5
	for {
		conn, aErr := ls.listener.Accept()
		if aErr != nil {
			// Listener closed or shutting down
			return
		}

		// Serve SOCKS5 on this connection in a goroutine
		go func(c net.Conn) {
			defer func() { _ = c.Close() }()
			ls.logger.DebugWith("Serving SOCKS5 connection",
				slog.F("remote", c.RemoteAddr()))
			if sErr := ls.server.ServeConn(c); sErr != nil {
				ls.logger.DebugWith("SOCKS5 connection error",
					slog.F("err", sErr))
			}
		}(conn)
	}
}

// Stop gracefully stops the SOCKS5 server
func (ls *LocalServer) Stop() error {
	close(ls.stopChan)
	return ls.listener.Close()
}
