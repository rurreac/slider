package client

import (
	"os"
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
