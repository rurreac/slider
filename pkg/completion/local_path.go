package completion

import (
	"context"
	"os"
)

const maxEntries = 100

// LocalPathCompleter completes paths on the local filesystem
type LocalPathCompleter struct{}

// NewLocalPathCompleter creates a new local path completer
func NewLocalPathCompleter() *LocalPathCompleter {
	return &LocalPathCompleter{}
}

// Complete performs local path completion
func (lpc *LocalPathCompleter) Complete(ctx context.Context, input string, cwd string, system string, homeDir string) ([]string, string, error) {
	// Parse input to get directory and prefix (with ~ expansion)
	dir, prefix, _ := parsePathInput(input, cwd, system, homeDir)

	// Read directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Directory doesn't exist or no permission
		return nil, input, nil
	}

	// Convert to FileInfo
	var fileInfos []os.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		fileInfos = append(fileInfos, info)
	}

	// Filter by prefix
	filtered := filterEntries(fileInfos, prefix, maxEntries)

	// Build result
	result := buildResult(filtered, prefix, system)

	// Return the expanded input as the common prefix base
	// This ensures ~ is fully expanded in the output
	return result.Matches, result.CommonPrefix, nil
}
