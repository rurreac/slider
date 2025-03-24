package ssocks

import (
	"io"
	"net"
	"slider/pkg/slog"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSocksInstance(t *testing.T) {
	logger := slog.NewLogger("TestSSocks")

	t.Run("New instance creation", func(t *testing.T) {
		config := &InstanceConfig{
			Logger: logger,
			LogID:  "[Test]",
			port:   12345,
		}

		instance := New(config)

		if instance == nil {
			t.Fatal("Failed to create socks instance")
		}

		if instance.port != 12345 {
			t.Errorf("Expected port 12345, got %d", instance.port)
		}

		if instance.LogID != "[Test]" {
			t.Errorf("Expected LogID '[Test]', got '%s'", instance.LogID)
		}

		if instance.IsEnabled() {
			t.Error("New instance should not be enabled")
		}
	})

	t.Run("Get endpoint port", func(t *testing.T) {
		config := &InstanceConfig{
			Logger: logger,
			port:   12345,
		}

		instance := New(config)
		instance.socksEnabled = true

		port, err := instance.GetEndpointPort()
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if port != 12345 {
			t.Errorf("Expected port 12345, got %d", port)
		}

		// Test non-enabled instance
		instance = New(config)

		_, err = instance.GetEndpointPort()
		if err == nil {
			t.Error("Expected error for non-endpoint instance, got nil")
		}
	})

	t.Run("Stop without running", func(t *testing.T) {
		config := &InstanceConfig{
			Logger: logger,
		}

		instance := New(config)

		err := instance.Stop()
		if err == nil {
			t.Error("Expected error when stopping non-running instance, got nil")
		}
	})
}

func TestSocksEndpointIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create a logger
	logger := slog.NewLogger("TestSSocksIntegration")

	// Setup mock SSH connection
	clientConn, serverConn := net.Pipe()

	// Create mock SSH connections
	mockSSHConn := &mockSSHConn{
		netConn: clientConn,
	}

	// Create a socks instance
	config := &InstanceConfig{
		Logger:  logger,
		LogID:   "[Test]",
		sshConn: mockSSHConn,
	}

	instance := New(config)

	// Start the endpoint in a goroutine
	errChan := make(chan error, 1)
	go func() {
		err := instance.StartEndpoint(0)
		errChan <- err
	}()

	// Wait for the endpoint to start
	time.Sleep(250 * time.Millisecond)

	// Check if port was assigned
	port, err := instance.GetEndpointPort()
	if err != nil {
		t.Fatalf("Failed to get endpoint port: %v", err)
	}

	if port == 0 {
		t.Fatal("port should be assigned by system")
	}

	// Verify instance is enabled
	if !instance.IsEnabled() {
		t.Error("Instance should be enabled after starting")
	}

	// Stop the endpoint
	err = instance.Stop()
	if err != nil {
		t.Fatalf("Failed to stop socks instance: %v", err)
	}

	// Wait for endpoint to fully stop
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Endpoint exited with error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timed out waiting for endpoint to stop")
	}

	// Verify instance is disabled
	if instance.IsEnabled() {
		t.Error("Instance should be disabled after stopping")
	}

	// Cleanup
	_ = clientConn.Close()
	_ = serverConn.Close()
}

// Mock SSH connection for testing
type mockSSHConn struct {
	netConn net.Conn
}

func (m *mockSSHConn) SendRequest(_ string, _ bool, _ []byte) (bool, []byte, error) {
	return true, nil, nil
}

func (m *mockSSHConn) OpenChannel(_ string, _ []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	// Create a mock channel using the net.Pipe connection
	channel := &mockChannel{
		netConn: m.netConn,
	}
	requests := make(chan *ssh.Request)
	close(requests) // No requests will be sent

	return channel, requests, nil
}

func (m *mockSSHConn) Close() error {
	return m.netConn.Close()
}

func (m *mockSSHConn) Wait() error {
	return nil
}

func (m *mockSSHConn) User() string {
	return "test-user"
}

func (m *mockSSHConn) SessionID() []byte {
	return []byte("test-session-id")
}

func (m *mockSSHConn) ClientVersion() []byte {
	return []byte("SSH-2.0-test-client")
}

func (m *mockSSHConn) ServerVersion() []byte {
	return []byte("SSH-2.0-test-server")
}

func (m *mockSSHConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
}

func (m *mockSSHConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2222}
}

// Mock SSH channel for testing
type mockChannel struct {
	netConn net.Conn
}

func (m *mockChannel) Read(data []byte) (int, error) {
	return m.netConn.Read(data)
}

func (m *mockChannel) Write(data []byte) (int, error) {
	return m.netConn.Write(data)
}

func (m *mockChannel) Close() error {
	return m.netConn.Close()
}

func (m *mockChannel) CloseWrite() error {
	return nil
}

func (m *mockChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) {
	return true, nil
}

func (m *mockChannel) Stderr() io.ReadWriter {
	return &discardReadWriter{}
}

// discardReadWriter implements io.ReadWriter with discarding behavior
type discardReadWriter struct{}

func (d *discardReadWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (d *discardReadWriter) Read(_ []byte) (n int, err error) {
	return 0, io.EOF
}
