package escseq

import (
	"bytes"
	"testing"
)

type mockTerminal struct {
	bytes.Buffer
	response string
}

func (m *mockTerminal) Read(p []byte) (n int, err error) {
	copy(p, m.response)
	return len(m.response), nil
}

func (m *mockTerminal) Write(p []byte) (n int, err error) {
	return m.Buffer.Write(p)
}

func TestScreenAlignment(t *testing.T) {
	mock := &mockTerminal{
		response: "\x1b[10;5R", // Row 10, Col 5
	}

	result := ScreenAlignment(mock)

	// Check if cursorRequest was written
	if !bytes.Contains(mock.Bytes(), cursorRequest) {
		t.Errorf("Expected cursor request %q to be written, got %q", cursorRequest, mock.Bytes())
	}

	// Expected result for row 10 is ESC [ 10 S followed by cursorHome
	expected := "\x1b[10S" + string(cursorHome)
	if result != expected {
		t.Errorf("Expected result %q, got %q", expected, result)
	}
}

func TestClearScreen(t *testing.T) {
	result := ClearScreen()
	expected := string(eraseScreen) + string(cursorHome)
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

func TestColorStripping(t *testing.T) {
	// Ensure colors are enabled by default or reset
	SetColors(true)
	if len(YellowText("test")) == 4 {
		t.Error("YellowText should contain escape sequences when colors are enabled")
	}

	SetColors(false)
	if YellowText("test") != "test" {
		t.Errorf("YellowText should be plain 'test' when colors are disabled, got %q", YellowText("test"))
	}

	// Reset for other tests
	SetColors(true)
}
