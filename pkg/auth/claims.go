package auth

import (
	"time"
)

// Claims represents the JWT claims structure for Slider authentication
type Claims struct {
	// Standard JWT claims
	Issuer    string `json:"iss"` // "slider-server" or "slider-client"
	Subject   string `json:"sub"` // Certificate fingerprint or key identifier
	IssuedAt  int64  `json:"iat"` // Unix timestamp
	ExpiresAt int64  `json:"exp"` // Unix timestamp

	// Custom claims
	CertID int64 `json:"cert_id,omitempty"` // Server only: certificate ID from cert jar
}

// NewClaims creates a new Claims instance with standard fields populated
func NewClaims(issuer, subject string, certID int64, lifetime time.Duration) *Claims {
	now := time.Now()
	return &Claims{
		Issuer:    issuer,
		Subject:   subject,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(lifetime).Unix(),
		CertID:    certID,
	}
}

// IsExpired checks if the token has expired
func (c *Claims) IsExpired() bool {
	return time.Now().Unix() > c.ExpiresAt
}

// IsValid performs basic validation on the claims
func (c *Claims) IsValid() bool {
	// Check required fields
	if c.Issuer == "" || c.Subject == "" {
		return false
	}

	// Check timestamps
	if c.IssuedAt <= 0 || c.ExpiresAt <= 0 {
		return false
	}

	// Check that expiration is after issuance
	if c.ExpiresAt <= c.IssuedAt {
		return false
	}

	// Check not expired
	if c.IsExpired() {
		return false
	}

	return true
}
