package sio

import (
	"bytes"
	"os"
	"testing"
)

func TestReadFile(t *testing.T) {
	// Create a temporary test file
	content := []byte("Test file content for testing ReadFile function")
	tmpFile, err := os.CreateTemp("", "test-read-file")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() { _ = os.Remove(tmpFile.Name()) }()

	if _, err := tmpFile.Write(content); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	_ = tmpFile.Close()

	// Test reading the file
	fileContent, checksum, err := ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	// Verify file content
	if !bytes.Equal(fileContent, content) {
		t.Errorf("File content mismatch. Expected %s, got %s", content, fileContent)
	}

	// Verify checksum is not empty
	if checksum == "" {
		t.Error("Checksum is empty")
	}

	// Test reading non-existent file
	_, _, err = ReadFile("non-existent-file")
	if err == nil {
		t.Error("Expected error when reading non-existent file, got nil")
	}
}
