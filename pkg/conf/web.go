package conf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
)

type VersionHolder struct {
	ProtoVersion string `json:"ProtoVersion"`
	Version      string `json:"version"`
}

type HttpHandler struct {
	TemplatePath string
	ServerHeader string
	StatusCode   int
	UrlRedirect  *url.URL
	ShowVersion  bool
}

var HttpVersionResponse = &VersionHolder{
	ProtoVersion: proto,
	Version:      version,
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

func TemplateExists(filePath string) error {
	fileInfo, fErr := os.Stat(filePath)
	if fErr != nil {
		return fmt.Errorf("file does not exist: %s", filePath)
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("%s is a directory", filePath)
	}

	return nil
}

func HandleHttpRequest(w http.ResponseWriter, r *http.Request, handler *HttpHandler) error {
	w.Header().Add("server", handler.ServerHeader)

	if handler.UrlRedirect.String() != "" {
		http.Redirect(w, r, handler.UrlRedirect.String(), http.StatusFound)
		return nil
	}

	switch r.URL.Path {
	case "/":
		if handler.TemplatePath != "" {
			tErr := TemplateExists(handler.TemplatePath)
			if tErr == nil {
				fb, rErr := os.ReadFile(handler.TemplatePath)
				if rErr != nil {
					return fmt.Errorf("failed to read HTTP template: %v", rErr)
				}
				w.WriteHeader(handler.StatusCode)
				_, _ = w.Write(fb)
				return nil
			}
			return fmt.Errorf("template \"%s\" is not accesible: %v", handler.TemplatePath, tErr)
		}
	case "/health":
		_, _ = w.Write([]byte("OK"))
		return nil
	case "/version":
		if handler.ShowVersion {
			r.Header.Add("Content-Type", "application/json")
			vRes, mErr := json.Marshal(HttpVersionResponse)
			if mErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Failed to process Version"))
			}
			_, _ = w.Write(vRes)
		}
		return nil
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found"))
	return nil
}
