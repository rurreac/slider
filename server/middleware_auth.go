package server

import (
	"net/http"
	"slider/pkg/auth"
	"strings"
)

const (
	// SliderTokenCookie is the name of the authentication cookie
	SliderTokenCookie = "slider_token"
)

// authMiddleware creates an HTTP middleware that validates JWT tokens
// It checks cookies first (for web clients), then Authorization header (for API clients)
// On failure:
//   - Browser requests (Accept: text/html): redirect to /auth
//   - API requests: return 401 Unauthorized
func (s *server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from cookie or header
		token := extractTokenFromRequest(r)

		if token == "" {
			s.handleUnauthorized(w, r, "Missing authentication token")
			return
		}

		// Validate token
		_, err := auth.Decode(token, s.getJWTSecret())
		if err != nil {
			s.handleUnauthorized(w, r, "Invalid or expired token")
			return
		}

		// Authentication successful, continue to next handler
		next.ServeHTTP(w, r)
	})
}

// extractTokenFromRequest extracts JWT token from cookie or Authorization header
// Checks cookie first (web clients), then header (API clients)
func extractTokenFromRequest(r *http.Request) string {
	// Try cookie first (for web browsers)
	if cookie, err := r.Cookie(SliderTokenCookie); err == nil {
		return cookie.Value
	}

	// Fallback to Authorization header (for API clients)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Expected format: "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
			return parts[1]
		}
	}

	return ""
}

// handleUnauthorized handles unauthorized access
// Redirects browsers to /auth, returns 401 for API clients
func (s *server) handleUnauthorized(w http.ResponseWriter, r *http.Request, message string) {
	// Check if request is from a browser (HTML accepted)
	acceptHeader := r.Header.Get("Accept")
	isBrowser := strings.Contains(acceptHeader, "text/html")

	if isBrowser {
		// Redirect to login page
		http.Redirect(w, r, "/auth", http.StatusSeeOther)
	} else {
		// Return JSON error for API clients
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized","error_description":"` + message + `"}`))
	}
}
