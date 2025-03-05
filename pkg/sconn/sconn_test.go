package sconn

import (
	"bytes"
	"io"
	"testing"
)

func TestSSHChannelToNetConn(t *testing.T) {
	// Create a mock SSH channel
	mockChannel := &mockSSHChannel{
		reader: bytes.NewReader([]byte("channel data")),
		writer: &bytes.Buffer{},
	}

	// Convert to net.Conn
	netConn := SSHChannelToNetConn(mockChannel)

	// Test basic functionality
	if netConn == nil {
		t.Fatal("SSHChannelToNetConn returned nil")
	}

	// Test reading
	buf := make([]byte, 12)
	n, err := netConn.Read(buf)
	if err != nil {
		t.Fatalf("Unexpected error on Read: %v", err)
	}
	if n != 12 || string(buf) != "channel data" {
		t.Errorf("Expected to read 'channel data', got '%s'", buf[:n])
	}

	// Test writing
	testData := []byte("channel response")
	n, err = netConn.Write(testData)
	if err != nil {
		t.Fatalf("Unexpected error on Write: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}

	// Verify data was written to the underlying channel
	writtenData := mockChannel.writer.(*bytes.Buffer).Bytes()
	if !bytes.Equal(writtenData, testData) {
		t.Errorf("Expected written data '%s', got '%s'", testData, writtenData)
	}

	// Test close
	err = netConn.Close()
	if err != nil {
		t.Fatalf("Unexpected error on Close: %v", err)
	}
	if !mockChannel.closed {
		t.Error("Expected SSH channel to be closed")
	}
}

// Mock SSH channel for testing
type mockSSHChannel struct {
	reader io.Reader
	writer io.Writer
	closed bool
}

func (m *mockSSHChannel) Read(data []byte) (int, error) {
	return m.reader.Read(data)
}

func (m *mockSSHChannel) Write(data []byte) (int, error) {
	return m.writer.Write(data)
}

func (m *mockSSHChannel) Close() error {
	m.closed = true
	return nil
}

func (m *mockSSHChannel) CloseWrite() error {
	return nil
}

func (m *mockSSHChannel) SendRequest(_ string, _ bool, _ []byte) (bool, error) {
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

func (d *discardReadWriter) Read(_ []byte) (n int, err error) {
	return 0, io.EOF
}
