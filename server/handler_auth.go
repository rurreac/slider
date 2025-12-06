package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"slider/pkg/auth"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
)

const (
	// DefaultTokenLifetime is the default JWT token validity period
	DefaultTokenLifetime = 24 * time.Hour
)

// TokenResponse is the JSON response for token exchange
type TokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	TokenType string `json:"token_type"`
}

// ErrorResponse is the JSON response for errors
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// TokenRequest is the JSON request for web clients
type TokenRequest struct {
	Fingerprint string `json:"fingerprint"`
}

// handleAuthToken exchanges a certificate fingerprint for a JWT token
// POST /auth/token
// Supports two authentication methods:
//  1. Header: X-Certificate-Fingerprint: <fingerprint> (API clients)
//  2. JSON body: {"fingerprint": "<fingerprint>"} (web clients)
//
// For web clients, sets JWT as httpOnly cookie in addition to JSON response
func (s *server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	// Only allow POST
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract fingerprint from header (API client) or JSON body (web client)
	fingerprint := r.Header.Get("X-Certificate-Fingerprint")
	isWebClient := false

	if fingerprint == "" {
		// Try to parse JSON body
		var req TokenRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			s.DebugWith("Auth token request rejected: invalid request format",
				slog.F("remote_addr", r.RemoteAddr),
				slog.F("err", err))
			sendErrorJSON(w, http.StatusBadRequest, "invalid_request", "Missing X-Certificate-Fingerprint header or valid JSON body")
			return
		}
		fingerprint = req.Fingerprint
		isWebClient = true
	}

	if fingerprint == "" {
		s.DebugWith("Auth token request rejected: missing fingerprint",
			slog.F("remote_addr", r.RemoteAddr))
		sendErrorJSON(w, http.StatusBadRequest, "invalid_request", "Missing fingerprint in request")
		return
	}

	// Validate fingerprint against server fingerprint first (id=0)
	var certID int64
	if fingerprint != s.fingerprint {
		// Validate fingerprint against cert jar
		if s.certTrack == nil || len(s.certTrack.Certs) == 0 {
			s.DebugWith("Auth token request rejected: no certificates available",
				slog.F("remote_addr", r.RemoteAddr),
				slog.F("fingerprint", fingerprint))
			sendErrorJSON(w, http.StatusUnauthorized, "unauthorized", "No certificates available for validation")
			return
		}

		var ok bool
		certID, ok = scrypt.IsAllowedFingerprint(fingerprint, s.certTrack.Certs)
		if !ok {
			s.DebugWith("Auth token request rejected: invalid fingerprint",
				slog.F("remote_addr", r.RemoteAddr),
				slog.F("fingerprint", fingerprint))
			sendErrorJSON(w, http.StatusUnauthorized, "invalid_fingerprint", "Certificate fingerprint not found")
			return
		}
	}

	// Generate JWT token
	claims := auth.NewClaims("slider-server", fingerprint, certID, DefaultTokenLifetime)
	token, err := auth.Encode(claims, s.getJWTSecret())
	if err != nil {
		s.ErrorWith("Failed to encode JWT token",
			slog.F("fingerprint", fingerprint),
			slog.F("cert_id", certID),
			slog.F("err", err))
		sendErrorJSON(w, http.StatusInternalServerError, "server_error", "Failed to generate token")
		return
	}

	// Log successful authentication
	s.DebugWith("Issued JWT token",
		slog.F("remote_addr", r.RemoteAddr),
		slog.F("fingerprint", fingerprint),
		slog.F("cert_id", certID),
		slog.F("web_client", isWebClient))

	// For web clients, set httpOnly cookie
	if isWebClient {
		http.SetCookie(w, &http.Cookie{
			Name:     SliderTokenCookie,
			Value:    token,
			Path:     "/",
			MaxAge:   int(DefaultTokenLifetime.Seconds()),
			HttpOnly: true,
			Secure:   r.TLS != nil, // Only set Secure flag if request is over HTTPS
			SameSite: http.SameSiteStrictMode,
		})
	}

	// Send JSON response (for both web and API clients)
	response := TokenResponse{
		Token:     token,
		ExpiresAt: time.Unix(claims.ExpiresAt, 0).Format(time.RFC3339),
		TokenType: "Bearer",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)
}

// getJWTSecret derives the JWT signing secret from the CA private key
func (s *server) getJWTSecret() []byte {
	return auth.DeriveSecret(s.CertificateAuthority.CAPrivateKey, "slider-jwt-v1")
}

// sendErrorJSON sends a JSON error response
func sendErrorJSON(w http.ResponseWriter, statusCode int, errorCode, description string) {
	response := ErrorResponse{
		Error:            errorCode,
		ErrorDescription: description,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}

// validateToken attempts to validate the token as a JWT first, then as a raw fingerprint
// Returns: fingerprint, certID, error
func (s *server) validateToken(token string) (string, int64, error) {
	// Try to decode as JWT first
	claims, err := auth.Decode(token, s.getJWTSecret())
	if err == nil {
		// JWT is valid, extract fingerprint and certID
		return claims.Subject, claims.CertID, nil
	}

	// JWT validation failed, try as raw fingerprint for backward compatibility
	if s.certTrack == nil || len(s.certTrack.Certs) == 0 {
		return "", 0, fmt.Errorf("no certificates available for validation")
	}

	certID, ok := scrypt.IsAllowedFingerprint(token, s.certTrack.Certs)
	if !ok {
		return "", 0, fmt.Errorf("invalid fingerprint")
	}

	// Token is a valid fingerprint
	return token, certID, nil
}

// handleLogout clears the authentication cookie
// POST /auth/logout
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Only allow POST
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Clear the cookie by setting it with a past expiration
	http.SetCookie(w, &http.Cookie{
		Name:     SliderTokenCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // Immediately expire
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	s.DebugWith("User logged out", slog.F("remote_addr", r.RemoteAddr))

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("Logged out successfully"))
}
