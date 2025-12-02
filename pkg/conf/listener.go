package conf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
	"slider/pkg/scrypt"
	"slider/pkg/types"
	"strings"
)

// 2MB is a lot for an HTML template, but just in case want to embed images
const maxTemplateSize = 2

var HttpVersionResponse = &types.VersionHolder{
	ProtoVersion: Proto,
	Version:      Version,
}

func CheckStatusCode(statusCode int) bool {
	acceptedCodes := []int{
		http.StatusOK,
		http.StatusMovedPermanently,
		http.StatusFound,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
	}

	return slices.Contains(acceptedCodes, statusCode)
}

func CheckTemplate(filePath string) error {
	fileInfo, fErr := os.Stat(filePath)
	if fErr != nil {
		return fmt.Errorf("\"%s\" does not exist", filePath)
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("\"%s\" is a directory", filePath)
	}
	sizeMiB := float64(fileInfo.Size()) / (BytesPerMB)
	if sizeMiB > maxTemplateSize {
		return fmt.Errorf("\"%s\" should be less than %dMiB", filePath, maxTemplateSize)
	}

	return nil
}

// getRouter returns a router configured for the given handler
// This allows dynamic route registration based on handler configuration
func getRouter(handler *types.HttpHandler) *Router {
	router := NewRouter()

	// Register basic routes
	router.HandleExact("/", handleRoot)
	if handler.HealthOn {
		router.HandleExact("/health", handleHealth)
	}
	if handler.VersionOn {
		router.HandleExact("/version", handleVersion)
	}

	// Register directory index with configurable path
	if handler.DirIndexOn && handler.DirIndexPath != "" {
		path := handler.DirIndexPath
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if !strings.HasSuffix(path, "/") {
			path += "/"
		}
		router.HandlePrefix(path, handleDirIndex)
	}

	// Register API
	if handler.ApiOn {
		router.HandlePrefix("/api/", handleAPI)
	}

	return router
}

func HandleHttpRequest(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	w.Header().Add("server", handler.ServerHeader)

	if handler.UrlRedirect.String() != "" {
		http.Redirect(w, r, handler.UrlRedirect.String(), http.StatusFound)
		return nil
	}

	// Get router configured for this handler
	router := getRouter(handler)

	// Route the request
	return router.ServeHTTP(w, r, handler)
}

// handleRoot serves the HTML template for the root path
func handleRoot(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	if handler.TemplatePath != "" {
		// Double-checking just in case the template was changed after starting up
		tErr := CheckTemplate(handler.TemplatePath)
		if tErr == nil {
			fb, rErr := os.ReadFile(handler.TemplatePath)
			if rErr != nil {
				return fmt.Errorf("failed to read HTTP template \"%v\"", rErr)
			}
			w.WriteHeader(handler.StatusCode)
			_, _ = w.Write(fb)
			return nil
		}
		return fmt.Errorf("template is not accessible: %v", tErr)
	}
	return nil
}

// handleHealth serves the health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	_, _ = w.Write([]byte("OK"))
	return nil
}

// handleVersion serves the version information as JSON
func handleVersion(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	w.Header().Add("Content-Type", "application/json")
	vRes, mErr := json.Marshal(HttpVersionResponse)
	if mErr != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Failed to process Version"))
		return mErr
	}
	_, _ = w.Write(vRes)
	return nil
}

// handleDirIndex serves directory listings and files
func handleDirIndex(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	prefix := handler.DirIndexPath
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	http.StripPrefix(prefix, http.FileServer(http.Dir("."))).ServeHTTP(w, r)
	return nil
}

// handleAPI handles REST API requests with fingerprint-based authentication
func handleAPI(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	// Validate Bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Authorization header required"))
		return fmt.Errorf("API access denied: missing authorization header")
	}

	// Extract token from "Bearer <token>"
	const bearerPrefix = "Bearer "
	if !strings.HasPrefix(authHeader, bearerPrefix) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Invalid authorization format. Use: Authorization: Bearer <fingerprint>"))
		return fmt.Errorf("API access denied: invalid authorization format")
	}

	token := strings.TrimPrefix(authHeader, bearerPrefix)

	// Validate token against cert jar
	if err := validateAPIToken(token, handler.CertTrack); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Invalid API token"))
		return fmt.Errorf("API access denied: %v", err)
	}

	// Future REST API implementation will go here
	w.WriteHeader(http.StatusNotImplemented)
	_, _ = w.Write([]byte("API not implemented"))
	return nil
}

// validateAPIToken validates a fingerprint token against the cert jar
func validateAPIToken(token string, certTrack *scrypt.CertTrack) error {
	if certTrack == nil || len(certTrack.Certs) == 0 {
		return fmt.Errorf("no certificates available for validation")
	}

	// Direct fingerprint lookup in cert jar
	if _, ok := scrypt.IsAllowedFingerprint(token, certTrack.Certs); !ok {
		return fmt.Errorf("fingerprint not found in certificate jar")
	}

	return nil
}
