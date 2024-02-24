package slog

import (
	"fmt"
	"io"
	"log"
	"os"
)

type LogBuff struct {
	io.Writer        // Writer to save log in a buffer
	io.Reader        // Reader to print buffer to stdout
	buff      []byte // Hold the logs while not using stdout
}

type Logger struct {
	debug   bool
	prefix  string
	logger  *log.Logger
	logBuff *LogBuff
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
		prefix:  prefix,
		logger:  log.New(os.Stdout, "", log.Ldate|log.Ltime),
		debug:   false,
		logBuff: lb,
	}
	return l
}

func (l *Logger) WithDebug() {
	l.debug = true
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
	l.logger.Printf(t, args...)
}

func (l *Logger) Debugf(t string, args ...interface{}) {
	if l.debug {
		l.logger.Printf(l.prefix+"[DEBUG] - "+t, args...)
	}
}

func (l *Logger) Warnf(t string, args ...interface{}) {
	if l.debug {
		l.logger.Printf(l.prefix+"[WARN] - "+t, args...)
	}
}

func (l *Logger) Infof(t string, args ...interface{}) {
	l.logger.Printf(l.prefix+" - "+t, args...)
}

func (l *Logger) Fatalf(t string, err error) {
	l.logger.Fatalf(l.prefix+"[FATAL] - "+t, err)
}

func (l *Logger) Errorf(t string, args ...interface{}) {
	l.logger.Printf(l.prefix+"[ERROR] - "+t, args...)
}
