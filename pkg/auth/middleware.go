package auth

import (
	"context"
	"net/http"
	"strings"
)

// ContextKey is the type for context keys in auth middleware
type ContextKey string

const (
	// ClaimsContextKey is the key for storing claims in request context
	ClaimsContextKey ContextKey = "auth_claims"
)

// Middleware creates an HTTP middleware that validates JWT tokens
// Tokens can be provided via:
// 1. Authorization: Bearer <token> header
// 2. ?token=<token> query parameter
func Middleware(secret []byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header or query param
			token := extractToken(r)

			if token == "" {
				http.Error(w, "Missing authentication token", http.StatusUnauthorized)
				return
			}

			// Decode and validate token
			claims, err := Decode(token, secret)
			if err != nil {
				switch err {
				case ErrExpiredToken:
					http.Error(w, "Token has expired", http.StatusUnauthorized)
				case ErrInvalidSignature, ErrInvalidToken, ErrInvalidClaims:
					http.Error(w, "Invalid token", http.StatusUnauthorized)
				default:
					http.Error(w, "Authentication failed", http.StatusUnauthorized)
				}
				return
			}

			// Add claims to request context
			ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)

			// Call next handler with updated context
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// extractToken extracts JWT token from request
// Checks Authorization header first, then query parameters
func extractToken(r *http.Request) string {
	// Try Authorization header first
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Expected format: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	// Fallback to query parameter (for WebSocket connections)
	return r.URL.Query().Get("token")
}

// GetClaims retrieves claims from request context
func GetClaims(r *http.Request) (*Claims, bool) {
	claims, ok := r.Context().Value(ClaimsContextKey).(*Claims)
	return claims, ok
}
