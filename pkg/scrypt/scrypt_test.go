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
	defer func() { _ = os.RemoveAll(tmpDir) }()

	serverKeyPair, kErr := ServerKeyPairFromFile(tmpPath)
	if kErr != nil {
		t.Fatalf("Failed to load Server Key: %v", kErr)
	}
	signer1, prErr := SignerFromKey(serverKeyPair.PrivateKey)
	if prErr != nil {
		t.Fatalf("Failed generate SSH signer: %v", prErr)
	}

	serverKeyPair2, k2Err := ServerKeyPairFromFile(tmpPath)
	if k2Err != nil {
		t.Fatalf("Failed to load Server Key: %v", k2Err)
	}
	signer2, pr2Err := SignerFromKey(serverKeyPair2.PrivateKey)
	if pr2Err != nil {
		t.Fatalf("Failed generate SSH signer: %v", pr2Err)
	}

	// Verify both signers have the same public key
	pubKey1 := base64.StdEncoding.EncodeToString(signer1.PublicKey().Marshal())
	pubKey2 := base64.StdEncoding.EncodeToString(signer2.PublicKey().Marshal())

	if pubKey1 != pubKey2 {
		t.Errorf("Public keys don't match after writing/reading:\n%s\n%s", pubKey1, pubKey2)
	}

	// Test with invalid file path
	_, err = ServerKeyPairFromFile("/non-existent-directory/non-existent-file")
	if err == nil {
		t.Error("Expected error with invalid file path, got nil")
	}
}
