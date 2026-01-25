package socks

import (
	"fmt"
	"net"
	"slider/pkg/slog"
	"testing"
	"time"
)

func TestLocalServer(t *testing.T) {
	logger := slog.NewLogger("test-socks")

	t.Run("Create and stop local server", func(t *testing.T) {
		ls, err := NewLocalServer(0, false, logger)
		if err != nil {
			t.Fatalf("Failed to create local SOCKS server: %v", err)
		}

		port := ls.Port()
		if port == 0 {
			t.Fatal("Port should be non-zero")
		}

		// Start in background
		go ls.Start()

		// Give it a moment to start
		time.Sleep(100 * time.Millisecond)

		// Verify we can connect to the port
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			t.Errorf("Failed to connect to SOCKS port: %v", err)
		} else {
			_ = conn.Close()
		}

		// Stop the server
		if err := ls.Stop(); err != nil {
			t.Errorf("Failed to stop local SOCKS server: %v", err)
		}
	})

	t.Run("Create with available port", func(t *testing.T) {
		// Find a free port
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		port := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()

		ls, err := NewLocalServer(port, false, logger)
		if err != nil {
			t.Fatalf("Failed to create local SOCKS server on port %d: %v", port, err)
		}

		if ls.Port() != port {
			t.Errorf("Expected port %d, got %d", port, ls.Port())
		}

		_ = ls.Stop()
	})
}
