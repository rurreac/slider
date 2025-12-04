package auth

import (
	"testing"
	"time"
)

func TestJWTEncodeDecodeRoundtrip(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")

	// Create claims
	claims := NewClaims("slider-server", "test-fingerprint-abc123", 42, 1*time.Hour)

	// Encode
	token, err := Encode(claims, secret)
	if err != nil {
		t.Fatalf("Failed to encode JWT: %v", err)
	}

	if token == "" {
		t.Fatal("Encoded token is empty")
	}

	// Decode
	decoded, err := Decode(token, secret)
	if err != nil {
		t.Fatalf("Failed to decode JWT: %v", err)
	}

	// Verify claims
	if decoded.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %s, want %s", decoded.Issuer, claims.Issuer)
	}
	if decoded.Subject != claims.Subject {
		t.Errorf("Subject mismatch: got %s, want %s", decoded.Subject, claims.Subject)
	}
	if decoded.CertID != claims.CertID {
		t.Errorf("CertID mismatch: got %d, want %d", decoded.CertID, claims.CertID)
	}
	if decoded.IssuedAt != claims.IssuedAt {
		t.Errorf("IssuedAt mismatch: got %d, want %d", decoded.IssuedAt, claims.IssuedAt)
	}
	if decoded.ExpiresAt != claims.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: got %d, want %d", decoded.ExpiresAt, claims.ExpiresAt)
	}
}

func TestJWTInvalidSignature(t *testing.T) {
	secret1 := []byte("secret-key-1-32-bytes-long!!!!")
	secret2 := []byte("secret-key-2-32-bytes-long!!!!")

	claims := NewClaims("slider-server", "test-fingerprint", 1, 1*time.Hour)

	// Encode with secret1
	token, err := Encode(claims, secret1)
	if err != nil {
		t.Fatalf("Failed to encode JWT: %v", err)
	}

	// Try to decode with secret2
	_, err = Decode(token, secret2)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got %v", err)
	}
}

func TestJWTExpiredToken(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")

	// Create expired token (already expired)
	claims := &Claims{
		Issuer:    "slider-server",
		Subject:   "test-fingerprint",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
		CertID:    1,
	}

	token, err := Encode(claims, secret)
	if err != nil {
		t.Fatalf("Failed to encode JWT: %v", err)
	}

	// Try to decode expired token
	_, err = Decode(token, secret)
	if err != ErrExpiredToken {
		t.Errorf("Expected ErrExpiredToken, got %v", err)
	}
}

func TestJWTInvalidFormat(t *testing.T) {
	secret := []byte("test-secret-key-32-bytes-long!!")

	testCases := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"single part", "xxx"},
		{"two parts", "xxx.yyy"},
		{"invalid base64", "!!invalid!!.!!invalid!!.!!invalid!!"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.token, secret)
			if err == nil {
				t.Errorf("Expected error for invalid token format, got nil")
			}
		})
	}
}

func TestClaimsValidation(t *testing.T) {
	testCases := []struct {
		name    string
		claims  *Claims
		isValid bool
	}{
		{
			name: "valid claims",
			claims: &Claims{
				Issuer:    "slider-server",
				Subject:   "fingerprint",
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
				CertID:    1,
			},
			isValid: true,
		},
		{
			name: "missing issuer",
			claims: &Claims{
				Subject:   "fingerprint",
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			},
			isValid: false,
		},
		{
			name: "missing subject",
			claims: &Claims{
				Issuer:    "slider-server",
				IssuedAt:  time.Now().Unix(),
				ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
			},
			isValid: false,
		},
		{
			name: "expired",
			claims: &Claims{
				Issuer:    "slider-server",
				Subject:   "fingerprint",
				IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
				ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
			},
			isValid: false,
		},
		{
			name: "expiration before issuance",
			claims: &Claims{
				Issuer:    "slider-server",
				Subject:   "fingerprint",
				IssuedAt:  time.Now().Add(1 * time.Hour).Unix(),
				ExpiresAt: time.Now().Unix(),
			},
			isValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid := tc.claims.IsValid()
			if valid != tc.isValid {
				t.Errorf("Expected IsValid() = %v, got %v", tc.isValid, valid)
			}
		})
	}
}

func TestHKDFSecretDerivation(t *testing.T) {
	masterKey := []byte("master-key-for-testing-purposes!")

	// Derive two secrets with the same info
	secret1 := DeriveSecret(masterKey, "slider-jwt-v1")
	secret2 := DeriveSecret(masterKey, "slider-jwt-v1")

	// Should be identical
	if len(secret1) != 32 {
		t.Errorf("Expected 32-byte secret, got %d bytes", len(secret1))
	}

	if string(secret1) != string(secret2) {
		t.Error("Derived secrets should be identical for same inputs")
	}

	// Derive with different info
	secret3 := DeriveSecret(masterKey, "different-purpose")

	// Should be different
	if string(secret1) == string(secret3) {
		t.Error("Derived secrets should differ when using different info strings")
	}
}
