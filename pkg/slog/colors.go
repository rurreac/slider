package slog

import "runtime"

var (
	DEBUG  = "[DEBUG]"
	INFO   = "[INFO]"
	WARN   = "[WARN]"
	ERROR  = "[ERROR]"
	FATAL  = "[FATAL]"
	Reset  string
	Red    string
	Green  string
	Yellow string
	Blue   string
	Purple string
	Cyan   string
	Gray   string
	White  string
)

func (l *Logger) WithColors() {
	if runtime.GOOS != "windows" {
		// Log Level
		DEBUG = "[" + Purple + "DEBUG" + Reset + "]"
		INFO = "[" + Cyan + "INFO" + Reset + "]"
		WARN = "[" + Yellow + "WARN" + Reset + "]"
		ERROR = "[" + Red + "ERROR" + Reset + "]"
		FATAL = "[" + Red + "FATAL" + Reset + "]"
		// Colors
		Reset = "\033[0m"
		Red = "\033[31m"
		Green = "\033[32m"
		Yellow = "\033[33m"
		Blue = "\033[34m"
		Purple = "\033[35m"
		Cyan = "\033[36m"
		Gray = "\033[37m"
		White = "\033[97m"
	}
}
