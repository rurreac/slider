package spath

import (
	"strings"
)

// unixIsPathSeparator checks if the byte is a Unix path separator
func unixIsPathSeparator(b byte) bool {
	return b == UnixSeparator
}

// unixToSlash ensures forward slashes in a path (converts backslashes to forward slashes)
func unixToSlash(path string) string {
	return replaceSlashes(path, WindowsSeparator, '/')
}

// unixIsAbs reports whether a Unix path is absolute
func unixIsAbs(path string) bool {
	return len(path) > 0 && path[0] == UnixSeparator
}

// unixJoin joins Unix path elements
func unixJoin(elem []string) string {
	// Find first non-empty element
	firstIdx := 0
	for i, e := range elem {
		if e != "" {
			firstIdx = i
			break
		}
	}

	// If all elements are empty, return empty string
	if firstIdx >= len(elem) {
		return ""
	}

	// Join all non-empty elements and clean the path
	var parts []string
	for _, e := range elem[firstIdx:] {
		if e != "" {
			parts = append(parts, e)
		}
	}

	return unixClean(strings.Join(parts, string(UnixSeparator)))
}

// unixDir returns the directory portion of a Unix path
func unixDir(path string) string {
	// Handle empty path
	if path == "" {
		return "."
	}

	// Find the last separator
	i := len(path) - 1
	for i >= 0 && !unixIsPathSeparator(path[i]) {
		i--
	}

	// If no separator found, return "."
	if i < 0 {
		return "."
	}

	// If root directory, return "/"
	if i == 0 {
		return string(UnixSeparator)
	}

	// Return everything up to the last separator, cleaned
	return unixClean(path[:i])
}

// unixBase returns the last element of a Unix path
func unixBase(path string) string {
	// Handle empty path
	if path == "" {
		return "."
	}

	// Strip trailing separators
	end := len(path)
	for end > 0 && unixIsPathSeparator(path[end-1]) {
		end--
	}

	if end == 0 {
		return string(UnixSeparator)
	}

	// Find the last separator
	i := end - 1
	for i >= 0 && !unixIsPathSeparator(path[i]) {
		i--
	}

	// Extract the base name (everything after the last separator)
	if i >= 0 {
		path = path[i+1 : end]
	} else {
		path = path[:end]
	}

	// If empty (had only separators), return a single separator
	if path == "" {
		return string(UnixSeparator)
	}

	return path
}

// unixClean cleans a Unix path
func unixClean(path string) string {
	// Handle empty path
	if path == "" {
		return "."
	}

	// Check if path starts with a separator
	rooted := len(path) > 0 && unixIsPathSeparator(path[0])

	// Split path into components
	components := []string{}

	// Skip empty components and handle dots
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || unixIsPathSeparator(path[i]) {
			// Extract component
			component := path[start:i]

			// Handle empty component and . component
			switch component {
			case "", ".":
				// Skip this component
			case "..":
				// Handle .. component
				if len(components) > 0 && components[len(components)-1] != ".." {
					// Can go up one level, remove the last component
					components = components[:len(components)-1]
				} else if !rooted {
					// Not rooted and can't go up, so keep the .. component
					components = append(components, "..")
				}
				// If rooted and can't go up, ignore the .. component
			default:
				// Add normal component
				components = append(components, component)
			}

			// Move to next component
			start = i + 1
		}
	}

	// Handle special case where path becomes empty
	if !rooted && len(components) == 0 {
		return "."
	}

	// Build the cleaned path
	var result strings.Builder

	// Add root separator if path was rooted
	if rooted {
		result.WriteByte(UnixSeparator)
	}

	// Add components with separators
	for i, component := range components {
		if i > 0 {
			result.WriteByte(UnixSeparator)
		}
		result.WriteString(component)
	}

	return result.String()
}
