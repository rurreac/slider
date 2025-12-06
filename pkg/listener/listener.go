package listener

import (
	"fmt"
	"net/http"
	"os"
	"slices"
	"slider/pkg/conf"
)

// 2MB is a lot for an HTML template, but just in case want to embed images
const maxTemplateSize = 2

type VersionHolder struct {
	ProtoVersion string `json:"ProtoVersion"`
	Version      string `json:"Version"`
}

var HttpVersionResponse = &VersionHolder{
	ProtoVersion: conf.Proto,
	Version:      conf.Version,
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
	sizeMiB := float64(fileInfo.Size()) / (conf.BytesPerMB)
	if sizeMiB > maxTemplateSize {
		return fmt.Errorf("\"%s\" should be less than %dMiB", filePath, maxTemplateSize)
	}

	return nil
}
