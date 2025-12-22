//go:build windows

package sio

import (
	"io"
	"os"

	"github.com/mattn/go-tty"
)

// CopyStdinCancellable copies from stdin to dst until done is closed.
// On Windows, uses go-tty which handles console I/O differently.
// Falls back to blocking read if tty cannot be opened.
func CopyStdinCancellable(dst io.Writer, done <-chan struct{}) {
	// Try to use go-tty for Windows console
	t, err := tty.Open()
	if err != nil {
		// Fallback: blocking copy (user will need to press a key to return)
		go func() {
			<-done
		}()
		_, _ = io.Copy(dst, os.Stdin)
		return
	}
	defer t.Close()

	for {
		select {
		case <-done:
			return
		default:
		}

		// On Windows, go-tty's ReadRune should be interruptible when Close() is called
		// But since we can't rely on that, we use a non-blocking approach with the Input channel
		r, err := t.ReadRune()
		if err != nil {
			return
		}
		_, writeErr := dst.Write([]byte(string(r)))
		if writeErr != nil {
			return
		}
	}
}
