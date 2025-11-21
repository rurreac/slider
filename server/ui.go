package server

import "io"

// UserInterface defines the contract for displaying information to users.
// Console implements this interface directly.
type UserInterface interface {
	// Message display methods
	PrintInfo(format string, args ...interface{})
	PrintWarn(format string, args ...interface{})
	PrintError(format string, args ...interface{})
	PrintSuccess(format string, args ...interface{})
	PrintDebug(format string, args ...interface{})

	// Writer returns the underlying writer for structured data (tables, etc.)
	Writer() io.Writer
}
