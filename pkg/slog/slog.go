package slog

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"slider/pkg/conf"
	"slider/pkg/escseq"
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
	colorOn bool
	blameOn bool
	jsonOn  bool
	prefix  string
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
		blameOn:  false,
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
	DEBU = escseq.LogDebug(colorOn)
	INFO = escseq.LogInfo(colorOn)
	WARN = escseq.LogWarn(colorOn)
	ERRO = escseq.LogError(colorOn)
	FATA = escseq.LogFatal(colorOn)
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
	if l.jsonOn {
		msg := fmt.Sprintf(t, args...)
		jsonMsg := l.formatAsJSON(msg, "", nil, "")
		l.logger.Println(jsonMsg)
	} else {
		l.logger.Printf(" - "+t, args...)
	}
}

func (l *Logger) Debugf(t string, args ...any) {
	if l.logLevel == lvlDebug {
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			jsonMsg := l.formatAsJSON(msg, "debug", nil, "")
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+DEBU+" "+t, args...)
		}
	}
}
func (l *Logger) DWarnf(t string, args ...any) {
	if l.logLevel == lvlDebug {
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			jsonMsg := l.formatAsJSON(msg, "warn", nil, "")
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+WARN+" "+t, args...)
		}
	}
}

func (l *Logger) DErrorf(t string, args ...any) {
	if l.logLevel == lvlDebug {
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			jsonMsg := l.formatAsJSON(msg, "error", nil, "")
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+ERRO+" "+t, args...)
		}
	}
}

func (l *Logger) Warnf(t string, args ...any) {
	if l.logLevel <= lvlWarn {
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			jsonMsg := l.formatAsJSON(msg, "warn", nil, "")
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+WARN+" "+t, args...)
		}
	}
}

func (l *Logger) Infof(t string, args ...any) {
	if l.logLevel <= lvlInfo {
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			jsonMsg := l.formatAsJSON(msg, "info", nil, "")
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+INFO+" "+t, args...)
		}
	}
}

func (l *Logger) Fatalf(t string, args ...any) {
	if l.jsonOn {
		msg := fmt.Sprintf(t, args...)
		jsonMsg := l.formatAsJSON(msg, "fatal", nil, "")
		l.logger.Fatalln(jsonMsg)
	} else {
		l.logger.Fatalf(" "+FATA+" "+t, args...)
	}
}

func (l *Logger) Errorf(t string, args ...any) {
	if l.logLevel <= lvlError {
		if l.jsonOn {
			msg := fmt.Sprintf(t, args...)
			jsonMsg := l.formatAsJSON(msg, "error", nil, "")
			l.logger.Println(jsonMsg)
		} else {
			l.logger.Printf(" "+ERRO+" "+t, args...)
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
		if verbosity == "BLAME" && conf.Version == "development" {
			l.logLevel = lvlDebug
			l.blameOn = true
			return nil
		}
		err = fmt.Errorf("expected one of [debug|info|warn|error|off]")
	}
	return err
}

// IsDebug returns true if the logger is set to debug level
func (l *Logger) IsDebug() bool {
	return l.logLevel == lvlDebug
}

// LoggerWithCaller is a temporary wrapper that adds caller information to the next log call
type LoggerWithCaller struct {
	logger *Logger
	caller string
}

// WithCaller returns a wrapper that will include caller information in the next log call
func (l *Logger) WithCaller() *LoggerWithCaller {
	// Get caller information (skip 1 frame: WithCaller itself)
	caller := ""
	if l.blameOn {
		_, file, line, ok := runtime.Caller(1)
		if ok {
			// Extract just the filename, not the full path
			caller = fmt.Sprintf(
				" <%s> ",
				escseq.GreyOut(
					fmt.Sprintf("%s:%d", filepath.Base(file), line),
					l.colorOn),
			)
		}
	}
	return &LoggerWithCaller{
		logger: l,
		caller: caller,
	}
}

// Printf logs with caller information
func (lc *LoggerWithCaller) Printf(t string, args ...any) {
	if lc.logger.jsonOn {
		msg := fmt.Sprintf(t, args...)
		callerInfo := ""
		if lc.caller != "" {
			callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
		}
		jsonMsg := lc.logger.formatAsJSON(msg, "", nil, callerInfo)
		lc.logger.logger.Println(jsonMsg)
	} else {
		msg := fmt.Sprintf(t, args...)
		lc.logger.logger.Printf(" %s%s", lc.caller, msg)
	}
}

// Debugf logs a debug message with caller information
func (lc *LoggerWithCaller) Debugf(t string, args ...any) {
	if lc.logger.logLevel == lvlDebug {
		if lc.logger.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "debug", nil, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			msg := fmt.Sprintf(t, args...)
			lc.logger.logger.Printf(" "+DEBU+" %s%s", lc.caller, msg)
		}
	}
}

// DWarnf logs a warning message with caller information (debug level only)
func (lc *LoggerWithCaller) DWarnf(t string, args ...any) {
	if lc.logger.logLevel == lvlDebug {
		if lc.logger.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "warn", nil, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			msg := fmt.Sprintf(t, args...)
			lc.logger.logger.Printf(" "+WARN+" %s%s", lc.caller, msg)
		}
	}
}

// DErrorf logs an error message with caller information (debug level only)
func (lc *LoggerWithCaller) DErrorf(t string, args ...any) {
	if lc.logger.logLevel == lvlDebug {
		if lc.logger.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "error", nil, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			msg := fmt.Sprintf(t, args...)
			lc.logger.logger.Printf(" "+ERRO+" %s%s", lc.caller, msg)
		}
	}
}

// Warnf logs a warning message with caller information
func (lc *LoggerWithCaller) Warnf(t string, args ...any) {
	if lc.logger.logLevel <= lvlWarn {
		if lc.logger.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "warn", nil, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			msg := fmt.Sprintf(t, args...)
			lc.logger.logger.Printf(" "+WARN+" %s%s", lc.caller, msg)
		}
	}
}

// Infof logs an info message with caller information
func (lc *LoggerWithCaller) Infof(t string, args ...any) {
	if lc.logger.logLevel <= lvlInfo {
		if lc.logger.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "info", nil, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			msg := fmt.Sprintf(t, args...)
			lc.logger.logger.Printf(" "+INFO+" %s%s", lc.caller, msg)
		}
	}
}

// Fatalf logs a fatal message with caller information and exits
func (lc *LoggerWithCaller) Fatalf(t string, args ...any) {
	if lc.logger.jsonOn {
		msg := fmt.Sprintf(t, args...)
		callerInfo := ""
		if lc.caller != "" {
			callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
		}
		jsonMsg := lc.logger.formatAsJSON(msg, "fatal", nil, callerInfo)
		lc.logger.logger.Fatalln(jsonMsg)
	} else {
		msg := fmt.Sprintf(t, args...)
		lc.logger.logger.Fatalf(" "+FATA+" %s%s", lc.caller, msg)
	}
}

// Errorf logs an error message with caller information
func (lc *LoggerWithCaller) Errorf(t string, args ...any) {
	if lc.logger.logLevel <= lvlError {
		if lc.logger.jsonOn {
			msg := fmt.Sprintf(t, args...)
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "error", nil, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			msg := fmt.Sprintf(t, args...)
			lc.logger.logger.Printf(" "+ERRO+" %s%s", lc.caller, msg)
		}
	}
}

// InfoWith logs an info message with structured fields and caller information
func (lc *LoggerWithCaller) InfoWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.logLevel <= lvlInfo {
		if lc.logger.jsonOn {
			callerInfo := ""
			if lc.caller != "" {
				// Extract caller from formatted string
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "info", fields, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			fmtFields := lc.logger.formatWithFields(msg, fields)
			if msgPrefix != nil {
				lc.logger.logger.Printf(" "+INFO+"%s%v - %s", lc.caller, msgPrefix, fmtFields)
			} else {
				lc.logger.logger.Printf(" "+INFO+"%s%s", lc.caller, fmtFields)
			}
		}
	}
}

// DebugWith logs a debug message with structured fields and caller information
func (lc *LoggerWithCaller) DebugWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.logLevel == lvlDebug {
		if lc.logger.jsonOn {
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "debug", fields, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			fmtFields := lc.logger.formatWithFields(msg, fields)
			if msgPrefix != nil {
				lc.logger.logger.Printf(" "+DEBU+"%s%v %s", lc.caller, msgPrefix, fmtFields)
			} else {
				lc.logger.logger.Printf(" "+DEBU+"%s%s", lc.caller, fmtFields)
			}
		}
	}
}

// WarnWith logs a warning message with structured fields and caller information
func (lc *LoggerWithCaller) WarnWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.logLevel <= lvlWarn {
		if lc.logger.jsonOn {
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "warn", fields, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			fmtFields := lc.logger.formatWithFields(msg, fields)
			if msgPrefix != nil {
				lc.logger.logger.Printf(" "+WARN+"%s%v - %s", lc.caller, msgPrefix, fmtFields)
			} else {
				lc.logger.logger.Printf(" "+WARN+"%s%s", lc.caller, fmtFields)
			}
		}
	}
}

// ErrorWith logs an error message with structured fields and caller information
func (lc *LoggerWithCaller) ErrorWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.logLevel <= lvlError {
		if lc.logger.jsonOn {
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "error", fields, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			fmtFields := lc.logger.formatWithFields(msg, fields)
			if msgPrefix != nil {
				lc.logger.logger.Printf(" "+ERRO+"%s%v %s", lc.caller, msgPrefix, fmtFields)
			} else {
				lc.logger.logger.Printf(" "+ERRO+"%s%s", lc.caller, fmtFields)
			}
		}
	}
}

// FatalWith logs a fatal message with structured fields and caller information, then exits
func (lc *LoggerWithCaller) FatalWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.jsonOn {
		callerInfo := ""
		if lc.caller != "" {
			callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
		}
		jsonMsg := lc.logger.formatAsJSON(msg, "fatal", fields, callerInfo)
		lc.logger.logger.Fatalln(jsonMsg)
	} else {
		fmtFields := lc.logger.formatWithFields(msg, fields)
		if msgPrefix != nil {
			lc.logger.logger.Fatalf(" "+FATA+"%s%v %s", lc.caller, msgPrefix, fmtFields)
		} else {
			lc.logger.logger.Fatalf(" "+FATA+"%s%s", lc.caller, fmtFields)
		}
	}
}

// DWarnWith logs a warning message with structured fields and caller information (debug level only)
func (lc *LoggerWithCaller) DWarnWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.logLevel == lvlDebug {
		if lc.logger.jsonOn {
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "warn", fields, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			fmtFields := lc.logger.formatWithFields(msg, fields)
			if msgPrefix != nil {
				lc.logger.logger.Printf(" "+WARN+"%s%v - %s", lc.caller, msgPrefix, fmtFields)
			} else {
				lc.logger.logger.Printf(" "+WARN+"%s%s", lc.caller, fmtFields)
			}
		}
	}
}

// DErrorWith logs an error message with structured fields and caller information (debug level only)
func (lc *LoggerWithCaller) DErrorWith(msg string, msgPrefix any, fields ...Field) {
	if lc.logger.logLevel == lvlDebug {
		if lc.logger.jsonOn {
			callerInfo := ""
			if lc.caller != "" {
				callerInfo = strings.Trim(strings.TrimSpace(lc.caller), "<>")
			}
			jsonMsg := lc.logger.formatAsJSON(msg, "error", fields, callerInfo)
			lc.logger.logger.Println(jsonMsg)
		} else {
			fmtFields := lc.logger.formatWithFields(msg, fields)
			if msgPrefix != nil {
				lc.logger.logger.Printf(" "+ERRO+"%s%v %s", lc.caller, msgPrefix, fmtFields)
			} else {
				lc.logger.logger.Printf(" "+ERRO+"%s%s", lc.caller, fmtFields)
			}
		}
	}
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
		sb.WriteString(escseq.GreyOut(field.Key+"=", l.colorOn))
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
