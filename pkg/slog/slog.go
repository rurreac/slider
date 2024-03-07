package slog

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

type LogBuff struct {
	io.Writer        // Writer to save log in a buffer
	io.Reader        // Reader to print buffer to stdout
	buff      []byte // Hold the logs while not using stdout
}

const levelDebug = 0
const levelInfo = 1
const levelWarn = 2
const levelError = 3
const separator = " - "

type Logger struct {
	logLevel int
	debug    bool
	logger   *log.Logger
	logBuff  *LogBuff
}

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
		logLevel: levelInfo,
		logger:   log.New(os.Stdout, prefix, log.LstdFlags|log.Lmsgprefix),
		debug:    false,
		logBuff:  lb,
	}
	return l
}

func (l *Logger) WithDebug() {
	l.logLevel = levelDebug
}
func (l *Logger) WithInfo() {
	l.logLevel = levelInfo
}

func (l *Logger) WithWarn() {
	l.logLevel = levelWarn
}

func (l *Logger) WithError() {
	l.logLevel = levelError
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
	l.Infof(t, args...)
}

func (l *Logger) Debugf(t string, args ...interface{}) {
	if l.logLevel == levelDebug {
		l.logger.Printf(DEBUG+separator+t, args...)
	}
}

func (l *Logger) Warnf(t string, args ...interface{}) {
	if l.logLevel <= levelWarn {
		l.logger.Printf(WARN+separator+t, args...)
	}
}

func (l *Logger) Infof(t string, args ...interface{}) {
	if l.logLevel <= levelInfo {
		l.logger.Printf(INFO+separator+t, args...)
	}
}

func (l *Logger) Fatalf(t string, err error) {
	l.logger.Fatalf(FATAL+separator+t, err)
}

func (l *Logger) Errorf(t string, args ...interface{}) {
	if l.logLevel <= levelError {
		l.logger.Printf(ERROR+separator+t, args...)
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
		return fmt.Errorf("incorrect log level, expected one of [DEBUG|INFO|WARN|ERROR]")
	}
	return nil
}
