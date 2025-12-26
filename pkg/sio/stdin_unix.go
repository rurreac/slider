//go:build !windows

package sio

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// CopyStdinCancellable copies from stdin to dst until done is closed.
// Uses select(2) with timeout to make the copy cancellable.
// Returns when either: done channel is closed, stdin returns EOF, or write to dst fails.
func CopyStdinCancellable(dst io.Writer, done <-chan struct{}) {
	stdinFd := int(os.Stdin.Fd())
	buf := make([]byte, 1024)

	for {
		// Check if we should stop
		select {
		case <-done:
			return
		default:
		}

		// Use select(2) with 50ms timeout to check if stdin has data
		var readfds unix.FdSet
		readfds.Zero()
		readfds.Set(stdinFd)

		// 50ms timeout - allows checking done channel regularly
		timeout := unix.Timeval{Sec: 0, Usec: 50000}

		n, err := unix.Select(stdinFd+1, &readfds, nil, nil, &timeout)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				// Interrupted by signal, just retry
				continue
			}
			// Actual error
			return
		}

		// Timeout (n == 0) - loop back and check done channel
		if n == 0 {
			continue
		}

		// stdin has data ready
		if readfds.IsSet(stdinFd) {
			nr, readErr := os.Stdin.Read(buf)
			if readErr != nil {
				return
			}
			if nr > 0 {
				_, writeErr := dst.Write(buf[:nr])
				if writeErr != nil {
					return
				}
			}
		}
	}
}
