package scrypt

import (
	"encoding/base64"
	"os"
	"testing"
)

func TestNewEd25519KeyPair(t *testing.T) {
	// Test key generation
	keyPair, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Verify key pair components
	if keyPair.PrivateKey == "" {
		t.Error("Private key is empty")
	}

	if keyPair.FingerPrint == "" {
		t.Error("Fingerprint is empty")
	}
}

func TestSignerFromKey(t *testing.T) {
	// Generate a key pair
	keyPair, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Test creating a signer from the key
	signer, err := SignerFromKey(keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create signer from key: %v", err)
	}

	// Verify that the signer is valid
	if signer == nil {
		t.Error("Signer is nil")
	}

	// Test with invalid key
	_, err = SignerFromKey("invalid-key-data")
	if err == nil {
		t.Error("Expected error with invalid key data, got nil")
	}
}

func TestFingerprintGeneration(t *testing.T) {
	// Generate a key pair
	keyPair, err := NewEd25519KeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Create signer to get the public key
	signer, err := SignerFromKey(keyPair.PrivateKey)
	if err != nil {
		t.Fatalf("Failed to create signer from key: %v", err)
	}

	// Generate fingerprint from public key
	fingerprint, err := GenerateFingerprint(signer.PublicKey())
	if err != nil {
		t.Fatalf("Failed to generate fingerprint: %v", err)
	}

	// Verify fingerprint is not empty
	if fingerprint == "" {
		t.Error("Generated fingerprint is empty")
	}

	// Generate fingerprint again and verify it's consistent
	fingerprint2, err := GenerateFingerprint(signer.PublicKey())
	if err != nil {
		t.Fatalf("Failed to regenerate fingerprint: %v", err)
	}

	// Verify both fingerprints match
	if fingerprint != fingerprint2 {
		t.Errorf("Fingerprints do not match: %s != %s", fingerprint, fingerprint2)
	}

	// Verify the fingerprint matches the one in the key pair
	if fingerprint != keyPair.FingerPrint {
		t.Errorf("Generated fingerprint does not match key pair's fingerprint: %s != %s",
			fingerprint, keyPair.FingerPrint)
	}
}

func TestSSHSignerFromFile(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "ssh-key-test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	tmpPath := tmpDir + "/testkey.json"
	// Clean up after the test
	defer os.RemoveAll(tmpDir)

	// Test with a non-existent file (will create a new key pair)
	signer1, err := NewSSHSignerFromFile(tmpPath)
	if err != nil {
		t.Fatalf("Failed to create signer from file: %v", err)
	}
	if signer1 == nil {
		t.Fatal("Signer is nil")
	}

	// Read the same file to get a signer
	signer2, err := NewSSHSignerFromFile(tmpPath)
	if err != nil {
		t.Fatalf("Failed to read signer from file: %v", err)
	}
	if signer2 == nil {
		t.Fatal("Second signer is nil")
	}

	// Verify both signers have the same public key
	pubKey1 := base64.StdEncoding.EncodeToString(signer1.PublicKey().Marshal())
	pubKey2 := base64.StdEncoding.EncodeToString(signer2.PublicKey().Marshal())

	if pubKey1 != pubKey2 {
		t.Errorf("Public keys don't match after writing/reading:\n%s\n%s", pubKey1, pubKey2)
	}

	// Test with invalid file path
	_, err = NewSSHSignerFromFile("/non-existent-directory/non-existent-file")
	if err == nil {
		t.Error("Expected error with invalid file path, got nil")
	}
}
