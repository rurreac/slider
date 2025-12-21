package interpreter

import "io"

// Pty defines a platform-independent interface for PTY operations
type Pty interface {
	io.ReadWriteCloser
	Resize(cols, rows uint32) error
	Wait() error
}
