package slog

import (
	"fmt"
	"io"
	"log"
	"os"
	"slider/pkg/escseq"
	"strings"
	"sync"
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
	colorOn  bool
	sync.Mutex
}

const (
	lvlDebug = 0
	lvlInfo  = 1
	lvlWarn  = 2
	lvlError = 3
	disabled = 9
)

var (
	DEBUG = "DEBU"
	INFO  = "INFO"
	WARN  = "WARN"
	ERROR = "ERRO"
	FATAL = "FATA"
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
	}
	return l
}

func NewDummyLog() *log.Logger {
	return log.New(io.Discard, "", 0)
}

func (l *Logger) WithColors() {
	l.colorOn = true
	// Log Level
	DEBUG = string(escseq.Log.Debug) + DEBUG + string(escseq.ResetColor)
	INFO = string(escseq.Log.Info) + INFO + string(escseq.ResetColor)
	WARN = string(escseq.Log.Warn) + WARN + string(escseq.ResetColor)
	ERROR = string(escseq.Log.Error) + ERROR + string(escseq.ResetColor)
	FATAL = string(escseq.Log.Fatal) + FATAL + string(escseq.ResetColor)
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

func (l *Logger) Printf(t string, args ...interface{}) {
	l.logger.Printf(" - "+t, args...)
}

func (l *Logger) Debugf(t string, args ...interface{}) {
	if l.logLevel == lvlDebug {
		l.logger.Printf(" "+DEBUG+" "+t, args...)
	}
}
func (l *Logger) DWarnf(t string, args ...interface{}) {
	if l.logLevel == lvlDebug {
		l.logger.Printf(" "+WARN+" "+t, args...)
	}
}

func (l *Logger) DErrorf(t string, args ...interface{}) {
	if l.logLevel == lvlDebug {
		l.logger.Printf(" "+ERROR+" "+t, args...)
	}
}

func (l *Logger) Warnf(t string, args ...interface{}) {
	if l.logLevel <= lvlWarn {
		l.logger.Printf(" "+WARN+" "+t, args...)
	}
}

func (l *Logger) Infof(t string, args ...interface{}) {
	if l.logLevel <= lvlInfo {
		l.logger.Printf(" "+INFO+" "+t, args...)
	}
}

func (l *Logger) Fatalf(t string, args ...interface{}) {
	l.logger.Fatalf(" "+FATAL+" "+t, args...)
}

func (l *Logger) Errorf(t string, args ...interface{}) {
	if l.logLevel <= lvlError {
		l.logger.Printf(" "+ERROR+" "+t, args...)
	}
}

func (l *Logger) SetLevel(verbosity string) error {
	switch strings.ToUpper(verbosity) {
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
		return fmt.Errorf("expected one of [debug|info|warn|error|off]")
	}
	return nil
}

// IsDebug returns true if the logger is set to debug level
func (l *Logger) IsDebug() bool {
	return l.logLevel == lvlDebug
}
