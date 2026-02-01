package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"slider/pkg/listener"
	"slider/pkg/slog"
)

// TestHandler_AuthRoutes verifies that auth routes are only registered when AuthOn is true
func TestHandler_AuthRoutes(t *testing.T) {
	tests := []struct {
		name         string
		authOn       bool
		path         string
		expectedCode int
	}{
		{
			name:         "AuthOn_AuthPage",
			authOn:       true,
			path:         listener.AuthPath,
			expectedCode: http.StatusOK, // Assuming templates are not loaded, might be 500 or 200 depending on handler
		},
		{
			name:         "AuthOff_AuthPage",
			authOn:       false,
			path:         listener.AuthPath,
			expectedCode: http.StatusNotFound,
		},
		{
			name:         "AuthOn_AuthLogin",
			authOn:       true,
			path:         listener.AuthLoginPath,
			expectedCode: http.StatusMethodNotAllowed, // GET on POST-only endpoint
		},
		{
			name:         "AuthOff_AuthLogin",
			authOn:       false,
			path:         listener.AuthLoginPath,
			expectedCode: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup minimal server
			logger := slog.NewLogger("test-auth-routes")
			s := &server{
				Logger:        logger,
				authOn:        tc.authOn,
				httpConsoleOn: true, // Must be enabled for auth routes to be considered
			}

			// Mock template path to avoid file errors if possible, or expect them
			// For this test we only care if the route IS REGISTERED, so 404 vs anything else is key.
			// However, handleAuthPage reads templates. Let's see.
			// handleAuthToken (AuthLoginPath) doesn't use templates, so that's a safer check for registration.

			// We need to build the router
			handler := s.buildRouter()

			req := httptest.NewRequest("GET", tc.path, nil)
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			if tc.expectedCode == http.StatusNotFound {
				if w.Code != http.StatusNotFound {
					t.Errorf("Expected 404 for path %s when authOn=%v, got %d", tc.path, tc.authOn, w.Code)
				}
			} else {
				// If we expect it to exist, we just want NOT 404
				if w.Code == http.StatusNotFound {
					t.Errorf("Expected route to exist for path %s when authOn=%v, but got 404", tc.path, tc.authOn)
				}
			}
		})
	}
}
