package auth

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

// DeriveSecret derives a JWT signing secret from a master key using HKDF
// This provides cryptographic key separation between different uses
func DeriveSecret(masterKey []byte, info string) []byte {
	// Use HKDF to derive a 32-byte secret
	h := hkdf.New(sha256.New, masterKey, nil, []byte(info))
	secret := make([]byte, 32)
	_, _ = h.Read(secret) // HKDF Read never returns an error
	return secret
}
