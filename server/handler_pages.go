package server

import (
	"html/template"
	"net/http"
	"path/filepath"
	"slider/pkg/slog"
	"sync"
)

var (
	// Template cache
	templates     *template.Template
	templatesOnce sync.Once
	templatesErr  error
)

// loadTemplates loads and parses all HTML templates
func loadTemplates(templateDir string) (*template.Template, error) {
	templatesOnce.Do(func() {
		pattern := filepath.Join(templateDir, "*.html")
		templates, templatesErr = template.ParseGlob(pattern)
	})
	return templates, templatesErr
}

// handleAuthPage serves the authentication/login page
func (s *server) handleAuthPage(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// If user is already authenticated, redirect to console
	if token := extractTokenFromRequest(r); token != "" {
		// Validate the token
		if _, _, err := s.validateToken(token); err == nil {
			// Valid token, redirect to console
			http.Redirect(w, r, "/console", http.StatusSeeOther)
			return
		}
		// Invalid token, continue to show login page
	}

	// Load templates
	tmpl, err := loadTemplates(s.templatePath)
	if err != nil {
		s.ErrorWith("Failed to load templates", slog.F("err", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "auth.html", nil); err != nil {
		s.ErrorWith("Failed to render auth template", slog.F("err", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleConsolePage serves the web terminal console page
func (s *server) handleConsolePage(w http.ResponseWriter, r *http.Request) {
	// Only allow GET requests
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authentication is already validated by middleware

	// Load templates
	tmpl, err := loadTemplates(s.templatePath)
	if err != nil {
		s.ErrorWith("Failed to load templates", slog.F("err", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "console.html", nil); err != nil {
		s.ErrorWith("Failed to render console template", slog.F("err", err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
