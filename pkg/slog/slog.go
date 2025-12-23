package slog

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

type LogBuff struct {
	io.Writer        // Writer to save log in a buffer
	io.Reader        // Reader to print buffer to stdout
	buff      []byte // Hold the logs while not using stdout
}

type Logger struct {
	logLevel int
	logger   *log.Logger
	logBuff  *LogBuff
	sync.Mutex
	colorOn  bool
	callerOn bool
	jsonOn   bool
	prefix   string
}

const (
	lvlDebug = 0
	lvlInfo  = 1
	lvlWarn  = 2
	lvlError = 3
	disabled = 9
)

var (
	DEBU = "DEBU"
	INFO = "INFO"
	WARN = "WARN"
	ERRO = "ERRO"
	FATA = "FATA"
)

func (lb *LogBuff) Write(p []byte) (int, error) {
	lb.buff = append(lb.buff, p...)
	return len(p), nil
}

func (lb *LogBuff) Read(p []byte) (int, error) {
	return len(p), nil
}

func NewLogger(prefix string) *Logger {
	// TODO: logBuff buff could be buffered and writes to buffer controlled according to its size
	lb := &LogBuff{
		buff: make([]byte, 0),
	}
	l := &Logger{
		logLevel: lvlInfo,
		logger:   log.New(os.Stdout, prefix, log.LstdFlags|log.Lmsgprefix),
		logBuff:  lb,
		colorOn:  false,
		callerOn: false,
		jsonOn:   false,
		prefix:   prefix,
	}
	return l
}

func NewDummyLog() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func (l *Logger) WithColors(colorOn bool) {
	// Log Level
	l.Lock()
	defer l.Unlock()
	l.colorOn = colorOn
	DEBU = colorDebug(colorOn)
	INFO = colorInfo(colorOn)
	WARN = colorWarn(colorOn)
	ERRO = colorError(colorOn)
	FATA = colorFatal(colorOn)
}

// WithJSON enables or disables JSON formatting for logs
func (l *Logger) WithJSON(jsonOn bool) {
	l.Lock()
	defer l.Unlock()
	l.jsonOn = jsonOn
	if jsonOn {
		// Disable colors when JSON is enabled
		l.colorOn = false
		// Remove timestamp and prefix from standard logger when using JSON
		l.logger.SetFlags(0)
		l.logger.SetPrefix("")
	} else {
		// Restore standard formatting
		l.logger.SetFlags(log.LstdFlags | log.Lmsgprefix)
		l.logger.SetPrefix(l.prefix)
	}
}

// WithCallerInfo enables or disables automatic caller information display for all logs
func (l *Logger) WithCallerInfo(enabled bool) {
	l.Lock()
	defer l.Unlock()
	l.callerOn = enabled
}

// getCallerIfEnabled returns caller information if callerOn is true, empty string otherwise
func (l *Logger) getCallerIfEnabled(skip int) string {
	if !l.callerOn {
		return ""
	}
	_, file, line, ok := runtime.Caller(skip + 1)
	if !ok {
		return ""
	}
	// For text output, format with brackets and grey color
	// For JSON output, this will be cleaned up by the caller
	return fmt.Sprintf(
		" <%s> ",
		colorGreyOut(
			fmt.Sprintf("%s:%d", filepath.Base(file), line),
			l.colorOn),
	)
}

func (l *Logger) LogToBuffer() {
	l.Lock()
	l.logger.SetOutput(l.logBuff)
	l.Unlock()
}

func (l *Logger) LogToStdout() {
	l.Lock()
	l.logger.SetOutput(os.Stdout)
	l.Unlock()
}

func (l *Logger) BufferOut() {
	fmt.Printf("%s", l.logBuff.buff)
	l.Lock()
	l.logBuff.buff = make([]byte, 0)
	l.Unlock()
}

func (l *Logger) Printf(t string, args ...any) {
	caller := l.getCallerIfEnabled(1)
	if l.jsonOn {
		msg := fmt.Sprintf(t, args...)
		callerInfo := ""
		if caller != "" {
			callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
		}
		jsonMsg := l.formatAsJSON(msg, "", nil, callerInfo)
		l.logger.Println(jsonMsg)
	} else {
		l.logger.Printf("  --  %s"+t, append([]any{caller}, args...)...)
	}
}

func (l *Logger) Debugf(t string, args ...any) {
	if l.logLevel == lvlDebug {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "debug", nil, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+DEBU+" %s"+t, append([]any{caller}, args...)...)
		}
	}
}
func (l *Logger) DWarnf(t string, args ...any) {
	if l.logLevel == lvlDebug {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "warn", nil, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+WARN+" %s"+t, append([]any{caller}, args...)...)
		}
	}
}

func (l *Logger) DErrorf(t string, args ...any) {
	if l.logLevel == lvlDebug {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "error", nil, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+ERRO+" %s"+t, append([]any{caller}, args...)...)
		}
	}
}

func (l *Logger) Warnf(t string, args ...any) {
	if l.logLevel <= lvlWarn {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "warn", nil, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+WARN+" %s"+t, append([]any{caller}, args...)...)
		}
	}
}

func (l *Logger) Infof(t string, args ...any) {
	if l.logLevel <= lvlInfo {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "info", nil, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+INFO+" %s"+t, append([]any{caller}, args...)...)
		}
	}
}

func (l *Logger) Fatalf(t string, args ...any) {
	caller := l.getCallerIfEnabled(1)
	if l.jsonOn {
		msg := fmt.Sprintf(t, args...)
		callerInfo := ""
		if caller != "" {
			callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
		}
		jsonMsg := l.formatAsJSON(msg, "fatal", nil, callerInfo)
		l.logger.Fatalln(jsonMsg)
	}
	l.logger.Fatalf(" "+FATA+" %s"+t, append([]any{caller}, args...)...)

}

func (l *Logger) Errorf(t string, args ...any) {
	if l.logLevel <= lvlError {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "error", nil, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+ERRO+" %s"+t, append([]any{caller}, args...)...)
		}
	}
}

// InfoWith logs an info message with structured fields
func (l *Logger) InfoWith(msg string, fields ...Field) {
	if l.logLevel <= lvlInfo {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "info", fields, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			fmtFields := l.formatWithFields(msg, fields)
			l.logger.Printf(" "+INFO+" %s%s", caller, fmtFields)
		}
	}
}

// DebugWith logs a debug message with structured fields
func (l *Logger) DebugWith(msg string, fields ...Field) {
	if l.logLevel == lvlDebug {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "debug", fields, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			fmtFields := l.formatWithFields(msg, fields)
			l.logger.Printf(" "+DEBU+" %s%s", caller, fmtFields)
		}
	}
}

// WarnWith logs a warning message with structured fields
func (l *Logger) WarnWith(msg string, fields ...Field) {
	if l.logLevel <= lvlWarn {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "warn", fields, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			fmtFields := l.formatWithFields(msg, fields)
			l.logger.Printf(" "+WARN+" %s%s", caller, fmtFields)
		}
	}
}

// ErrorWith logs an error message with structured fields
func (l *Logger) ErrorWith(msg string, fields ...Field) {
	if l.logLevel <= lvlError {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "error", fields, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			fmtFields := l.formatWithFields(msg, fields)
			l.logger.Printf(" "+ERRO+" %s%s", caller, fmtFields)
		}
	}
}

// FatalWith logs a fatal message with structured fields, then exits
func (l *Logger) FatalWith(msg string, fields ...Field) {
	caller := l.getCallerIfEnabled(1)
	if l.jsonOn {
		callerInfo := ""
		if caller != "" {
			callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
		}
		jsonMsg := l.formatAsJSON(msg, "fatal", fields, callerInfo)
		l.logger.Fatalln(jsonMsg)
	}
	fmtFields := l.formatWithFields(msg, fields)
	l.logger.Fatalf(" "+FATA+" %s%s", caller, fmtFields)
}

// DWarnWith logs a warning message with structured fields (debug level only)
func (l *Logger) DWarnWith(msg string, fields ...Field) {
	if l.logLevel == lvlDebug {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "warn", fields, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			fmtFields := l.formatWithFields(msg, fields)
			l.logger.Printf(" "+WARN+" %s%s", caller, fmtFields)
		}
	}
}

// DErrorWith logs an error message with structured fields (debug level only)
func (l *Logger) DErrorWith(msg string, fields ...Field) {
	if l.logLevel == lvlDebug {
		caller := l.getCallerIfEnabled(1)
		if l.jsonOn {
			callerInfo := ""
			if caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(caller), "<>")
			}
			jsonMsg := l.formatAsJSON(msg, "error", fields, callerInfo)
			l.logger.Println(jsonMsg)
		} else {
			fmtFields := l.formatWithFields(msg, fields)
			l.logger.Printf(" "+ERRO+" %s%s", caller, fmtFields)
		}
	}
}

func (l *Logger) SetLevel(verbosity string) error {
	var err error
	verbosity = strings.ToUpper(verbosity)
	switch verbosity {
	case "DEBUG":
		l.logLevel = lvlDebug
	case "INFO":
		l.logLevel = lvlInfo
	case "WARN":
		l.logLevel = lvlWarn
	case "ERROR":
		l.logLevel = lvlError
	case "OFF":
		l.logLevel = disabled
	default:
		err = fmt.Errorf("expected one of [debug|info|warn|error|off]")
	}
	return err
}

// IsDebug returns true if the logger is set to debug level
func (l *Logger) IsDebug() bool {
	return l.logLevel == lvlDebug
}

// Field represents a structured log field with a key-value pair
type Field struct {
	Key   string
	Value any
}

// F is a helper function to create a Field for structured logging
func F(key string, value any) Field {
	return Field{Key: key, Value: value}
}

// P is a helper function to create a Field for structured logging as message prefix
func P(scope string) string {
	return fmt.Sprintf("%s - ", scope)
}

// formatWithFields formats a message with structured fields
func (l *Logger) formatWithFields(msg string, fields []Field) string {
	if l.jsonOn {
		return l.formatAsJSON(msg, "", fields, "")
	}

	if len(fields) == 0 {
		return msg
	}

	var sb strings.Builder
	sb.WriteString(msg)

	for _, field := range fields {
		sb.WriteString(" ")
		sb.WriteString(colorGreyOut(field.Key+"=", l.colorOn))
		switch field.Value.(type) {
		case int, int64, uint, uint64, float64, float32:
			sb.WriteString(fmt.Sprintf("%v", field.Value))
		default:
			sb.WriteString(fmt.Sprintf("\"%v\"", field.Value))
		}
	}

	return sb.String()
}

// formatAsJSON formats a log entry as JSON
func (l *Logger) formatAsJSON(msg string, level string, fields []Field, caller string) string {
	logEntry := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"scope":     l.prefix,
		"message":   msg,
	}

	if level != "" {
		logEntry["level"] = level
	}

	if caller != "" {
		logEntry["caller"] = caller
	}

	// Add structured fields
	for _, field := range fields {
		logEntry[field.Key] = field.Value
	}

	jsonBytes, err := json.Marshal(logEntry)
	if err != nil {
		// Fallback to plain text if JSON marshaling fails
		return fmt.Sprintf("JSON_ERROR: %v - %s", err, msg)
	}

	return string(jsonBytes)
}
