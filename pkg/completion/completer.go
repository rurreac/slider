package completion

import (
	"context"
	"os"
)

// PathCompleter provides path completion functionality
type PathCompleter interface {
	// Complete returns completion suggestions for the given input
	// homeDir is the user's home directory for ~ expansion
	Complete(ctx context.Context, input string, cwd string, system string, homeDir string) ([]string, string, error)
}

// CompletionResult holds the results of a completion operation
type CompletionResult struct {
	Matches      []string // All matching entries
	CommonPrefix string   // Common prefix of all matches
	NeedsQuoting bool     // Whether result needs quoting due to spaces
}

// parsePathInput parses user input to determine the directory to search and the prefix to match
func parsePathInput(input, cwd, system, homeDir string) (dir, prefix string, expandedInput string) {
	expandedInput = input

	if input == "" {
		return cwd, "", expandedInput
	}

	// Handle home directory expansion first
	if input == "~" {
		if homeDir == "" {
			return cwd, "", expandedInput
		}
		return homeDir, "", homeDir
	}

	// Expand ~/... paths
	if len(input) >= 2 && input[0] == '~' && (input[1] == '/' || input[1] == '\\') {
		if homeDir == "" {
			// If we can't get home dir, treat ~ as literal
			return cwd, input, expandedInput
		}
		// Replace ~ with home directory
		expandedInput = homeDir + input[1:] // Keep the separator
		input = expandedInput
	}

	// Check if input contains path separator
	var sep string
	if system == "windows" {
		// Windows can use both separators
		if lastBackslash := findLast(input, '\\'); lastBackslash > findLast(input, '/') {
			sep = "\\"
		} else if findLast(input, '/') >= 0 {
			sep = "/"
		}
	} else {
		if findLast(input, '/') >= 0 {
			sep = "/"
		}
	}

	if sep == "" {
		// No separator, complete in current directory
		return cwd, input, expandedInput
	}

	// Split into directory and prefix parts
	lastSepIdx := findLast(input, rune(sep[0]))
	dirPart := input[:lastSepIdx+1]
	prefix = input[lastSepIdx+1:]

	// Determine absolute directory
	if isAbsPath(dirPart, system) {
		dir = dirPart
	} else {
		dir = joinPath(system, cwd, dirPart)
	}

	return dir, prefix, expandedInput
}

// filterEntries filters directory entries based on prefix (case-insensitive)
func filterEntries(entries []os.FileInfo, prefix string, maxEntries int) []os.FileInfo {
	if prefix == "" && len(entries) <= maxEntries {
		return entries
	}

	var matches []os.FileInfo
	for _, entry := range entries {
		// Skip hidden files unless prefix starts with dot
		if len(prefix) == 0 && entry.Name()[0] == '.' {
			continue
		}

		if matchesPrefix(entry.Name(), prefix) {
			matches = append(matches, entry)
			if len(matches) >= maxEntries {
				break
			}
		}
	}

	return matches
}

// matchesPrefix checks if name matches prefix (case-insensitive)
func matchesPrefix(name, prefix string) bool {
	if prefix == "" {
		return true
	}

	if len(name) < len(prefix) {
		return false
	}

	for i := 0; i < len(prefix); i++ {
		if toLower(name[i]) != toLower(prefix[i]) {
			return false
		}
	}

	return true
}

// buildResult constructs the completion result from filtered entries
func buildResult(entries []os.FileInfo, prefix, system string) CompletionResult {
	result := CompletionResult{
		Matches: make([]string, 0, len(entries)),
	}

	if len(entries) == 0 {
		result.CommonPrefix = prefix
		return result
	}

	// Add separator for directories
	sep := "/"
	if system == "windows" {
		sep = "\\"
	}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += sep
		}
		result.Matches = append(result.Matches, name)

		// Check if needs quoting
		if !result.NeedsQuoting && containsSpace(name) {
			result.NeedsQuoting = true
		}
	}

	// Find common prefix
	if len(result.Matches) == 1 {
		result.CommonPrefix = result.Matches[0]
	} else {
		result.CommonPrefix = findCommonPrefix(result.Matches)
	}

	return result
}

// findCommonPrefix finds the common prefix among all matches
func findCommonPrefix(matches []string) string {
	if len(matches) == 0 {
		return ""
	}

	if len(matches) == 1 {
		return matches[0]
	}

	prefix := matches[0]
	for _, match := range matches[1:] {
		for i := 0; i < len(prefix) && i < len(match); i++ {
			if toLower(prefix[i]) != toLower(match[i]) {
				prefix = prefix[:i]
				break
			}
		}
	}

	return prefix
}

// Helper functions

func findLast(s string, c rune) int {
	for i := len(s) - 1; i >= 0; i-- {
		if rune(s[i]) == c {
			return i
		}
	}
	return -1
}

func isAbsPath(path, system string) bool {
	if system == "windows" {
		// Check for drive letter (C:) or UNC path (\\)
		if len(path) >= 2 && path[1] == ':' {
			return true
		}
		if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
			return true
		}
		// Also handle forward slash absolute paths on Windows
		if len(path) >= 2 && path[0] == '/' && path[1] != '/' {
			return false // relative with forward slash
		}
		if len(path) >= 3 && path[0] == '/' && path[2] == ':' {
			return true // /C:/path style
		}
		return false
	}
	// Unix: absolute if starts with /
	return len(path) > 0 && path[0] == '/'
}

func joinPath(system, base, rel string) string {
	if system == "windows" {
		// Normalize separators
		base = normalizeWindowsPath(base)
		rel = normalizeWindowsPath(rel)

		if base == "" {
			return rel
		}
		if rel == "" {
			return base
		}

		// Remove trailing separator from base
		if base[len(base)-1] == '\\' {
			base = base[:len(base)-1]
		}

		return base + "\\" + rel
	}

	// Unix
	if base == "" {
		return rel
	}
	if rel == "" {
		return base
	}

	// Remove trailing separator from base
	if base[len(base)-1] == '/' {
		base = base[:len(base)-1]
	}

	return base + "/" + rel
}

func normalizeWindowsPath(path string) string {
	// Convert forward slashes to backslashes
	result := make([]byte, len(path))
	for i := 0; i < len(path); i++ {
		if path[i] == '/' {
			result[i] = '\\'
		} else {
			result[i] = path[i]
		}
	}
	return string(result)
}

func toLower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func containsSpace(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			return true
		}
	}
	return false
}
