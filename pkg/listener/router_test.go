package listener

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	cfg := &RouterConfig{
		HealthOn:     true,
		ServerHeader: "test-server",
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(body) != "OK" {
		t.Errorf("Expected body 'OK', got '%s'", string(body))
	}

	if resp.Header.Get("server") != "test-server" {
		t.Errorf("Expected server header 'test-server', got '%s'", resp.Header.Get("server"))
	}
}

func TestHealthHandlerDisabled(t *testing.T) {
	cfg := &RouterConfig{
		HealthOn: false,
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 when health disabled, got %d", resp.StatusCode)
	}
}

func TestVersionHandler(t *testing.T) {
	cfg := &RouterConfig{
		VersionOn:    true,
		ServerHeader: "test-server",
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/version", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", resp.Header.Get("Content-Type"))
	}

	if len(body) == 0 {
		t.Error("Expected non-empty JSON body")
	}
}

func TestVersionHandlerDisabled(t *testing.T) {
	cfg := &RouterConfig{
		VersionOn: false,
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/version", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 when version disabled, got %d", resp.StatusCode)
	}
}

func TestTemplateHandler(t *testing.T) {
	// Create a temporary template file
	tmpDir := t.TempDir()
	templatePath := filepath.Join(tmpDir, "test.html")
	templateContent := "<html><body>Test Template</body></html>"

	if err := os.WriteFile(templatePath, []byte(templateContent), 0644); err != nil {
		t.Fatal(err)
	}

	cfg := &RouterConfig{
		TemplatePath: templatePath,
		StatusCode:   http.StatusOK,
		ServerHeader: "test-server",
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(body) != templateContent {
		t.Errorf("Expected body '%s', got '%s'", templateContent, string(body))
	}
}

func TestTemplateHandlerNoTemplate(t *testing.T) {
	cfg := &RouterConfig{
		StatusCode: http.StatusNotFound,
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", resp.StatusCode)
	}
}

func TestTemplateHandlerNonRootPath(t *testing.T) {
	cfg := &RouterConfig{
		StatusCode: http.StatusOK,
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/nonexistent", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 for non-root path, got %d", resp.StatusCode)
	}
}

func TestDirIndexHandler(t *testing.T) {
	// Create a temporary directory with a test file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.txt")
	testContent := "test content"

	if err := os.WriteFile(testFile, []byte(testContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Change to temp dir for the test
	oldWd, _ := os.Getwd()
	defer func() { _ = os.Chdir(oldWd) }()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatal(err)
	}

	cfg := &RouterConfig{
		DirIndexOn:   true,
		DirIndexPath: "/files",
		ServerHeader: "test-server",
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/files/test.txt", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	if string(body) != testContent {
		t.Errorf("Expected body '%s', got '%s'", testContent, string(body))
	}
}

func TestDirIndexHandlerDisabled(t *testing.T) {
	cfg := &RouterConfig{
		DirIndexOn: false,
	}

	mux := NewRouter(cfg)

	req := httptest.NewRequest("GET", "/files/test.txt", nil)
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("Expected status 404 when dir index disabled, got %d", resp.StatusCode)
	}
}

func TestRouterMultipleEndpoints(t *testing.T) {
	cfg := &RouterConfig{
		HealthOn:     true,
		VersionOn:    true,
		StatusCode:   http.StatusOK,
		ServerHeader: "test-server",
	}

	mux := NewRouter(cfg)

	tests := []struct {
		path           string
		expectedStatus int
	}{
		{"/health", http.StatusOK},
		{"/version", http.StatusOK},
		{"/", http.StatusNotFound}, // No template
		{"/nonexistent", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.path, nil)
			w := httptest.NewRecorder()

			mux.ServeHTTP(w, req)

			resp := w.Result()

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("Path %s: expected status %d, got %d", tt.path, tt.expectedStatus, resp.StatusCode)
			}
		})
	}
}
