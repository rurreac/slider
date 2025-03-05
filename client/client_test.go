package client

import (
	"encoding/json"
	"io"
	"net"
	"os"
	"slider/pkg/conf"
	"slider/pkg/slog"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestClientAuthenticationWithKey(t *testing.T) {
	// Create a test client
	log := slog.NewLogger("TestClient")
	c := client{
		Logger: log,
		sshConfig: &ssh.ClientConfig{
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			ClientVersion:   "SSH-slider-test-client",
			Timeout:         time.Second * 5,
		},
	}

	// Test valid key
	t.Run("Valid key authentication", func(t *testing.T) {
		testKey := `MC4CAQAwBQYDK2VwBCIEILTiS2hH1XPy+MYZn8tJXG8HJzQSJH0V/vU45QV5krBP`

		err := c.enableKeyAuth(testKey)
		if err != nil {
			t.Errorf("Failed to enable key authentication: %v", err)
		}

		if len(c.sshConfig.Auth) == 0 {
			t.Error("No authentication methods set")
		}
	})

	// Test invalid key
	t.Run("Invalid key authentication", func(t *testing.T) {
		invalidKey := "invalid-key-data"

		err := c.enableKeyAuth(invalidKey)
		if err == nil {
			t.Error("Expected error with invalid key, got nil")
		}
	})
}

func TestClientFingerprintLoading(t *testing.T) {
	log := slog.NewLogger("TestClient")
	c := client{
		Logger: log,
	}

	// Test direct fingerprint
	t.Run("Direct fingerprint", func(t *testing.T) {
		fp := "11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff"
		err := c.loadFingerPrint(fp)

		if err != nil {
			t.Errorf("Failed to load fingerprint: %v", err)
		}

		if len(c.serverFingerprint) != 1 || c.serverFingerprint[0] != fp {
			t.Errorf("Fingerprint not properly saved, got: %v", c.serverFingerprint)
		}
	})

	// Test fingerprint from file
	t.Run("Fingerprint from file", func(t *testing.T) {
		// Create temporary file with fingerprints
		tmpFile, err := os.CreateTemp("", "fingerprints")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Remove(tmpFile.Name()) }()

		fingerprints := []string{
			"11:22:33:44:55:66:77:88:99:00:aa:bb:cc:dd:ee:ff",
			"aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00",
		}

		for _, fp := range fingerprints {
			if _, err := tmpFile.WriteString(fp + "\n"); err != nil {
				t.Fatal(err)
			}
		}
		_ = tmpFile.Close()

		// Reset client fingerprints
		c.serverFingerprint = nil

		// Load from file
		err = c.loadFingerPrint(tmpFile.Name())
		if err != nil {
			t.Errorf("Failed to load fingerprints from file: %v", err)
		}

		if len(c.serverFingerprint) != len(fingerprints) {
			t.Errorf("Expected %d fingerprints, got %d", len(fingerprints), len(c.serverFingerprint))
		}

		for i, fp := range fingerprints {
			if c.serverFingerprint[i] != fp {
				t.Errorf("Fingerprint mismatch at position %d. Expected %s, got %s", i, fp, c.serverFingerprint[i])
			}
		}
	})
}

func TestSendClientInfo(t *testing.T) {
	// Create a test session
	s := &Session{
		Logger: slog.NewLogger("TestSession"),
		sshConn: &mockSSHConn{
			requestSuccess: true,
		},
		logID: "[Test]",
	}

	// Test sending client info
	clientInfo := &conf.ClientInfo{
		Interpreter: nil, // Using nil instead of string
	}

	s.sendClientInfo(clientInfo)

	// Check if the request was sent with correct data
	mockConn := s.sshConn.(*mockSSHConn)
	if mockConn.requestType != "client-info" {
		t.Errorf("Expected request type 'client-info', got '%s'", mockConn.requestType)
	}

	var receivedInfo conf.ClientInfo
	if err := json.Unmarshal(mockConn.requestPayload, &receivedInfo); err != nil {
		t.Errorf("Failed to unmarshal request payload: %v", err)
	}
}

// Mock SSH connection for testing
type mockSSHConn struct {
	requestSuccess  bool
	requestType     string
	requestPayload  []byte
	channelData     interface{}              // Buffer to store channel data
	channelToReturn ssh.Channel              // Channel to return from OpenChannel
	replySent       bool                     // Flag to track if a reply was sent
	replyHandler    func(bool, []byte) error // Custom handler for request replies
}

func (m *mockSSHConn) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	m.requestType = name
	m.requestPayload = payload
	return m.requestSuccess, []byte("test-response"), nil
}

func (m *mockSSHConn) OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	// If a specific channel is provided, return it
	if m.channelToReturn != nil {
		requests := make(chan *ssh.Request)
		close(requests) // No requests will be sent
		return m.channelToReturn, requests, nil
	}

	// Otherwise create a mock channel
	channel := &mockSSHChannel{
		readWriter: m.channelData,
	}
	requests := make(chan *ssh.Request)
	close(requests) // No requests will be sent
	return channel, requests, nil
}

func (m *mockSSHConn) Close() error {
	return nil
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

// Mock SSH channel with custom read/write support
type mockSSHChannel struct {
	readWriter interface{}
	closed     bool
}

func (m *mockSSHChannel) Read(data []byte) (int, error) {
	if m.readWriter == nil {
		return 0, io.EOF
	}
	if r, ok := m.readWriter.(io.Reader); ok {
		return r.Read(data)
	}
	return 0, io.EOF
}

func (m *mockSSHChannel) Write(data []byte) (int, error) {
	if m.readWriter == nil {
		return len(data), nil
	}
	if w, ok := m.readWriter.(io.Writer); ok {
		return w.Write(data)
	}
	return len(data), nil
}

func (m *mockSSHChannel) Close() error {
	m.closed = true
	return nil
}

func (m *mockSSHChannel) CloseWrite() error {
	return nil
}

func (m *mockSSHChannel) SendRequest(name string, wantReply bool, payload []byte) (bool, error) {
	return true, nil
}

func (m *mockSSHChannel) Stderr() io.ReadWriter {
	return &discardReadWriter{}
}

// discardReadWriter implements io.ReadWriter
type discardReadWriter struct{}

func (d *discardReadWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (d *discardReadWriter) Read(p []byte) (n int, err error) {
	return 0, io.EOF
}
