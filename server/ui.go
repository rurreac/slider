package server

import "io"

// UserInterface defines the contract for outputting messages to the user.
// It provides methods for different message types (info, warn, error, success, debug)
// and access to the underlying writer for custom formatting.
type UserInterface interface {
	PrintInfo(format string, args ...any)
	PrintWarn(format string, args ...any)
	PrintError(format string, args ...any)
	PrintSuccess(format string, args ...any)
	PrintDebug(format string, args ...any)
	PrintlnGreyOut(format string, args ...any)
	Printf(format string, args ...any)
	FlatPrintf(format string, args ...any)
	clearScreen()
	CenterScreen()
	Reset()
	Writer() io.Writer
}
