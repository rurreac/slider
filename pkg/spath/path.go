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

// SFTPPathForDisplay converts an SFTP path (always Unix-style) to display format
// based on the remote system type.
// For Windows: /C:/Users/user → C:\Users\user
// For Unix: /home/user → /home/user (unchanged)
func SFTPPathForDisplay(sftpPath, system string) string {
	if system != "windows" {
		return sftpPath
	}

	// Windows: Convert /C:/Users/user → C:\Users\user
	path := strings.TrimPrefix(sftpPath, "/")
	path = strings.ReplaceAll(path, "/", "\\")
	return path
}

// UserInputToSFTPPath converts user input to SFTP format (Unix-style paths)
// This handles both absolute and relative paths for any OS combination.
func UserInputToSFTPPath(userPath, currentSFTPPath, system string) string {
	if system != "windows" {
		// Unix system: straightforward
		if strings.HasPrefix(userPath, "/") {
			return userPath // Already absolute Unix path
		}
		// Relative path: join with current directory
		return UnixJoin(currentSFTPPath, userPath)
	}

	// Windows system: need to convert to SFTP format
	// Check if it's an absolute Windows path (C:\Users or C:/Users)
	if len(userPath) >= 2 && userPath[1] == ':' {
		// Convert C:\Users → /C:/Users or C:/Users → /C:/Users
		path := strings.ReplaceAll(userPath, "\\", "/")
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return path
	}

	// Relative path: normalize slashes and join with current directory
	path := strings.ReplaceAll(userPath, "\\", "/")
	return UnixJoin(currentSFTPPath, path)
}

// UnixJoin joins paths using Unix path rules (forward slashes)
// This is used for SFTP operations which always use Unix-style paths
func UnixJoin(elem ...string) string {
	return unixJoin(elem)
}

// UnixDir returns the directory portion of a Unix-style path
// This is used for SFTP operations which always use Unix-style paths
func UnixDir(path string) string {
	return unixDir(path)
}
