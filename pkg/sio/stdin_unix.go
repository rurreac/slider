//go:build !windows

package sio

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// CopyInteractiveCancellable copies from src to dst until done is closed.
// Uses select(2) with timeout to make the copy cancellable if src is a file.
// Returns when either: done channel is closed, src returns EOF, or write to dst fails.
func CopyInteractiveCancellable(dst io.Writer, src io.Reader, done <-chan struct{}) {
	var fd int
	var isFile bool

	if f, ok := src.(*os.File); ok {
		fd = int(f.Fd())
		isFile = true
	} else if f, ok := src.(interface{ Fd() uintptr }); ok {
		fd = int(f.Fd())
		isFile = true
	}

	if !isFile {
		// Fallback for non-file readers: blocking copy
		// We still use os.Stdin as a last resort if it matches what was originally intended
		// but ideally we should just copy from src.
		go func() {
			<-done
		}()
		_, _ = io.Copy(dst, src)
		return
	}

	buf := make([]byte, 1024)

	for {
		// Check if we should stop
		select {
		case <-done:
			return
		default:
		}

		// Use select(2) with 50ms timeout to check if fd has data
		var readfds unix.FdSet
		readfds.Zero()
		readfds.Set(fd)

		// 50ms timeout - allows checking done channel regularly
		timeout := unix.Timeval{Sec: 0, Usec: 50000}

		n, err := unix.Select(fd+1, &readfds, nil, nil, &timeout)
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

		// fd has data ready
		if readfds.IsSet(fd) {
			nr, readErr := src.Read(buf)
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
