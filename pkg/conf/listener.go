package conf

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"slices"
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

func HandleHttpRequest(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	w.Header().Add("server", handler.ServerHeader)

	switch r.URL.Path {
	case "/":
		if handler.TemplatePath != "" {
			// Double-checking just in case the template was changed after stating up
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
			return fmt.Errorf("template is not accesible: %v", tErr)
		}
	case "/health":
		if handler.HealthOn {
			_, _ = w.Write([]byte("OK"))
			return nil
		}
	case "/version":
		if handler.VersionOn {
			r.Header.Add("Content-Type", "application/json")
			vRes, mErr := json.Marshal(HttpVersionResponse)
			if mErr != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte("Failed to process Version"))
			}
			_, _ = w.Write(vRes)
			return nil
		}
	default:
		if handler.DirIndexOn {
			if strings.HasPrefix(r.URL.Path, handler.DirIndexPath) {
				return handleDirIndex(w, r, handler)
			}
		}
		return nil
	}
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("Not found"))
	return nil
}

// handleDirIndex serves directory listings and files
func handleDirIndex(w http.ResponseWriter, r *http.Request, handler *types.HttpHandler) error {
	prefix := handler.DirIndexPath
	if !strings.HasPrefix(prefix, "/") {
		prefix = "/" + prefix
	}
	if !strings.HasSuffix(prefix, "/") {
		prefix += "/"
	}
	http.StripPrefix(prefix, http.FileServer(http.Dir("."))).ServeHTTP(w, r)
	return nil
}
