// Package spath provides functionality for manipulating file paths
// for different operating systems independently of the runtime OS.
package spath

import (
	"strings"
)

// Constants for path separators
const (
	WindowsSeparator = '\\'
	UnixSeparator    = '/'
)

// IsAbs reports whether the path is absolute.
// It takes a system parameter to determine which OS rules to use.
func IsAbs(system, path string) bool {
	if system == "windows" {
		return winIsAbs(path)
	}
	return unixIsAbs(path)
}

// Join joins any number of path elements into a single path, separating
// them with the OS-specific separator.
func Join(system string, elem []string) string {
	if system == "windows" {
		return winJoin(elem)
	}
	return unixJoin(elem)
}

// Dir returns all but the last element of path, typically the path's directory.
func Dir(system, path string) string {
	if system == "windows" {
		return winDir(path)
	}
	return unixDir(path)
}

// Base returns the last element of path.
func Base(system, path string) string {
	if system == "windows" {
		return winBase(path)
	}
	return unixBase(path)
}

// FromToSlash converts a path to use the OS-specific separator.
// On Windows, it converts forward slashes to backslashes.
// On Unix, it ensures forward slashes are used.
func FromToSlash(system, path string) string {
	if system == "windows" {
		return winFromSlash(path)
	}
	return unixToSlash(path)
}

// replaceSlashes replaces all instances of oldChar with newChar in a string
func replaceSlashes(s string, oldChar, newChar byte) string {
	// If the string doesn't contain the old character, return it unchanged
	if !strings.ContainsRune(s, rune(oldChar)) {
		return s
	}

	// Create a new byte slice and replace the characters
	bytes := []byte(s)
	for i := 0; i < len(bytes); i++ {
		if bytes[i] == oldChar {
			bytes[i] = newChar
		}
	}

	return string(bytes)
}
