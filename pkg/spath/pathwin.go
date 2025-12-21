package spath

import (
	"strings"
)

// Windows reserved file names
var windowsReservedNames = []string{
	"CON", "PRN", "AUX", "NUL",
	"COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
	"LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
}

// winIsPathSeparator checks if the byte is a Windows path separator
func winIsPathSeparator(b byte) bool {
	return b == '\\' || b == '/'
}

// winFromSlash replaces forward slashes with Windows path separators
func winFromSlash(path string) string {
	return replaceSlashes(path, '/', WindowsSeparator)
}

// winIsReservedName checks if the path is a Windows reserved name
func winIsReservedName(path string) bool {
	if path == "" {
		return false
	}

	// Check if the path (ignoring case) matches any reserved name
	upperPath := strings.ToUpper(path)
	for _, reserved := range windowsReservedNames {
		if upperPath == reserved {
			return true
		}
	}

	return false
}

// winVolumeNameLength returns the length of the volume name in a Windows path
func winVolumeNameLength(path string) int {
	// Handle paths that are too short for a volume name
	if len(path) < 2 {
		return 0
	}

	// Check for drive letter (e.g., "C:")
	if path[1] == ':' {
		c := path[0]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return 2
		}
	}

	// Check for UNC path (e.g., "\\server\share")
	if len(path) >= 2 && winIsPathSeparator(path[0]) && winIsPathSeparator(path[1]) {
		// Skip leading backslashes
		i := 2
		if i >= len(path) {
			return 0
		}

		// Skip server name
		for i < len(path) && !winIsPathSeparator(path[i]) {
			i++
		}

		if i >= len(path) {
			return 0
		}

		// Skip separator after server name
		i++
		if i >= len(path) {
			return 0
		}

		// Skip share name
		start := i
		for i < len(path) && !winIsPathSeparator(path[i]) {
			i++
		}

		if start < i {
			return i
		}
	}

	return 0
}

// winVolumeName returns the volume name from a Windows path
func winVolumeName(path string) string {
	volLen := winVolumeNameLength(path)
	if volLen == 0 {
		return ""
	}
	return winFromSlash(path[:volLen])
}

// winIsAbs reports whether a Windows path is absolute
func winIsAbs(path string) bool {
	if winIsReservedName(path) {
		return true
	}

	volLen := winVolumeNameLength(path)
	if volLen == 0 {
		return false
	}

	// Check for UNC path (which is always absolute)
	if len(path) >= 2 && winIsPathSeparator(path[0]) && winIsPathSeparator(path[1]) {
		return true
	}

	// Path has a volume name, check if it starts with a separator after the volume
	path = path[volLen:]
	return len(path) > 0 && winIsPathSeparator(path[0])
}

// winJoin joins Windows path elements
func winJoin(elem []string) string {
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

	// Handle the case where the first element is a drive letter
	first := elem[firstIdx]
	isDriveLetter := len(first) == 2 && first[1] == ':'

	if isDriveLetter {
		// Handle drive letter specially
		var parts []string

		// Add the drive letter
		parts = append(parts, first)

		// Add remaining non-empty elements
		for _, e := range elem[firstIdx+1:] {
			if e != "" {
				parts = append(parts, e)
			}
		}

		// Clean the joined path
		return winClean(strings.Join(parts, string(WindowsSeparator)))
	} else {
		// Check if first element is a UNC path
		isUNC := len(first) > 0 && winIsPathSeparator(first[0]) &&
			(len(first) > 1 && winIsPathSeparator(first[1]))

		// Join all non-empty elements
		var parts []string
		for _, e := range elem[firstIdx:] {
			if e != "" {
				parts = append(parts, e)
			}
		}

		joined := winClean(strings.Join(parts, string(WindowsSeparator)))

		// Preserve UNC path status
		if isUNC && !strings.HasPrefix(joined, string(WindowsSeparator)+string(WindowsSeparator)) {
			if strings.HasPrefix(joined, string(WindowsSeparator)) {
				// Add one more separator at the beginning
				return string(WindowsSeparator) + joined
			} else {
				// Add two separators at the beginning
				return string(WindowsSeparator) + string(WindowsSeparator) + joined
			}
		}

		return joined
	}
}

// winDir returns the directory portion of a Windows path
func winDir(path string) string {
	// Get volume name
	vol := winVolumeName(path)

	// Find the last separator
	i := len(path) - 1
	for i >= len(vol) && !winIsPathSeparator(path[i]) {
		i--
	}

	// Get the directory part (everything up to and including the last separator)
	dir := winClean(path[len(vol) : i+1])

	// Handle UNC root paths
	if dir == "." && len(vol) > 2 {
		// must be UNC
		return vol
	}

	return vol + dir
}

// winBase returns the last element of a Windows path
func winBase(path string) string {
	// Handle empty path
	if path == "" {
		return "."
	}

	// Strip trailing separators
	end := len(path)
	for end > 0 && winIsPathSeparator(path[end-1]) {
		end--
	}

	if end == 0 {
		return string(WindowsSeparator)
	}

	// Skip volume name
	volLen := winVolumeNameLength(path)
	path = path[volLen:end]

	// Find the last separator
	i := len(path) - 1
	for i >= 0 && !winIsPathSeparator(path[i]) {
		i--
	}

	// Extract the base name (everything after the last separator)
	if i >= 0 {
		path = path[i+1:]
	}

	// If empty (had only separators), return a single separator
	if path == "" {
		return string(WindowsSeparator)
	}

	return path
}

// winClean cleans a Windows path
func winClean(path string) string {
	// Handle empty path
	if path == "" {
		return "."
	}

	// Get volume name
	volLen := winVolumeNameLength(path)
	vol := ""
	if volLen > 0 {
		vol = path[:volLen]
		path = path[volLen:]
	}

	// Check if path starts with a separator
	rooted := len(path) > 0 && winIsPathSeparator(path[0])

	// Split path into components
	components := []string{}

	// Skip empty components and handle dots
	start := 0
	for i := 0; i <= len(path); i++ {
		if i == len(path) || winIsPathSeparator(path[i]) {
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

	// Add volume name
	result.WriteString(winFromSlash(vol))

	// Add root separator if path was rooted
	if rooted {
		result.WriteByte(WindowsSeparator)
	}

	// Add components with separators
	for i, component := range components {
		if i > 0 {
			result.WriteByte(WindowsSeparator)
		}
		result.WriteString(component)
	}

	// Handle path with only the root slash
	if rooted && len(components) == 0 {
		return result.String()
	}

	return result.String()
}
