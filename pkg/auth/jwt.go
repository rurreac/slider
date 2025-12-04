package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// JWT header for HS256 algorithm
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

var (
	// Standard JWT header for HS256
	standardHeader = header{
		Alg: "HS256",
		Typ: "JWT",
	}

	// ErrInvalidToken is returned when token format is invalid
	ErrInvalidToken = fmt.Errorf("invalid token format")

	// ErrInvalidSignature is returned when signature verification fails
	ErrInvalidSignature = fmt.Errorf("invalid signature")

	// ErrExpiredToken is returned when token has expired
	ErrExpiredToken = fmt.Errorf("token has expired")

	// ErrInvalidClaims is returned when claims fail validation
	ErrInvalidClaims = fmt.Errorf("invalid claims")
)

// Encode creates a JWT token from claims using HS256 algorithm
func Encode(claims *Claims, secret []byte) (string, error) {
	// Encode header
	headerBytes, err := json.Marshal(standardHeader)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// Encode claims
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to marshal claims: %w", err)
	}
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Create signature
	message := headerB64 + "." + claimsB64
	signature := sign(message, secret)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine all parts
	token := message + "." + signatureB64

	return token, nil
}

// Decode parses and validates a JWT token
func Decode(token string, secret []byte) (*Claims, error) {
	// Split token into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerB64 := parts[0]
	claimsB64 := parts[1]
	signatureB64 := parts[2]

	// Verify signature
	message := headerB64 + "." + claimsB64
	expectedSignature := sign(message, secret)
	expectedSignatureB64 := base64.RawURLEncoding.EncodeToString(expectedSignature)

	if !hmac.Equal([]byte(signatureB64), []byte(expectedSignatureB64)) {
		return nil, ErrInvalidSignature
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}

	// Verify algorithm
	if h.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", h.Alg)
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(claimsB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}

	// Validate claims
	if !claims.IsValid() {
		if claims.IsExpired() {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidClaims
	}

	return &claims, nil
}

// sign creates an HMAC-SHA256 signature
func sign(message string, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(message))
	return h.Sum(nil)
}
