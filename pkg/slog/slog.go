package slog

import (
	"fmt"
	"io"
	"log"
	"os"
	"slider/pkg/colors"
	"strings"
)

type LogBuff struct {
	io.Writer        // Writer to save log in a buffer
	io.Reader        // Reader to print buffer to stdout
	buff      []byte // Hold the logs while not using stdout
}

type Logger struct {
	LogLevel int
	debug    bool
	logger   *log.Logger
	logBuff  *LogBuff
	colorOn  bool
}

const LvlDebug = 0
const LvlInfo = 1
const LvlWarn = 2
const LvlError = 3

var (
	DEBUG = " DEBU "
	INFO  = " INFO "
	WARN  = " WARN "
	ERROR = " ERRO "
	FATAL = " FATA "
)

func (lb *LogBuff) Write(p []byte) (int, error) {
	lb.buff = append(lb.buff, p...)
	return len(p), nil
}

func (lb *LogBuff) Read(p []byte) (int, error) {
	return len(p), nil
}

func NewLogger(prefix string) *Logger {
	// TODO: LogBuff buff could be buffered and writes to buffer controlled according to its size
	lb := &LogBuff{
		buff: make([]byte, 0),
	}
	l := &Logger{
		LogLevel: LvlInfo,
		logger:   log.New(os.Stdout, prefix, log.LstdFlags|log.Lmsgprefix),
		debug:    false,
		logBuff:  lb,
	}
	return l
}

func (l *Logger) WithDebug() {
	l.LogLevel = LvlDebug
}
func (l *Logger) WithInfo() {
	l.LogLevel = LvlInfo
}

func (l *Logger) WithWarn() {
	l.LogLevel = LvlWarn
}

func (l *Logger) WithError() {
	l.LogLevel = LvlError
}

func (l *Logger) WithColors() {
	l.colorOn = true
	// Log Level
	DEBUG = string(colors.Log.Debug) + DEBUG + string(colors.Reset)
	INFO = string(colors.Log.Info) + INFO + string(colors.Reset)
	WARN = string(colors.Log.Warn) + WARN + string(colors.Reset)
	ERROR = string(colors.Log.Error) + ERROR + string(colors.Reset)
	FATAL = string(colors.Log.Fatal) + FATAL + string(colors.Reset)
}

func (l *Logger) LogToBuffer() {
	l.logger.SetOutput(l.logBuff)
}

func (l *Logger) LogToStdout() {
	l.logger.SetOutput(os.Stdout)
}

func (l *Logger) BufferOut() {
	fmt.Printf("%s", l.logBuff.buff)
	l.logBuff.buff = make([]byte, 0)
}

func (l *Logger) Printf(t string, args ...interface{}) {
	l.logger.Printf(" - "+t, args...)
}

func (l *Logger) Debugf(t string, args ...interface{}) {
	if l.LogLevel == LvlDebug {
		l.logger.Printf(DEBUG+t, args...)
	}
}

func (l *Logger) Warnf(t string, args ...interface{}) {
	if l.LogLevel <= LvlWarn {
		l.logger.Printf(WARN+t, args...)
	}
}

func (l *Logger) Infof(t string, args ...interface{}) {
	if l.LogLevel <= LvlInfo {
		l.logger.Printf(INFO+t, args...)
	}
}

func (l *Logger) Fatalf(t string, err error) {
	l.logger.Fatalf(FATAL+t, err)
}

func (l *Logger) Errorf(t string, args ...interface{}) {
	if l.LogLevel <= LvlError {
		l.logger.Printf(ERROR+t, args...)
	}
}

func (l *Logger) SetLevel(verbosity string) error {
	switch strings.ToUpper(verbosity) {
	case "DEBUG":
		l.WithDebug()
	case "INFO":
		l.WithInfo()
	case "WARN":
		l.WithWarn()
	case "ERROR":
		l.WithError()
	default:
		return fmt.Errorf("wrong log level, expected one of [debug|info|warn|error]")
	}
	return nil
}
