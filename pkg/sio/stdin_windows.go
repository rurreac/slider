//go:build windows

package sio

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// CopyInteractiveCancellable copies from src to dst until done is closed.
// Uses WaitForSingleObject with timeout to make the copy cancellable if src is a file.
// Returns when either: done channel is closed, src returns EOF, or write to dst fails.
func CopyInteractiveCancellable(dst io.Writer, src io.Reader, done <-chan struct{}) {
	var handle windows.Handle
	var isFile bool

	if f, ok := src.(*os.File); ok {
		handle = windows.Handle(f.Fd())
		isFile = true
	} else if f, ok := src.(interface{ Fd() uintptr }); ok {
		handle = windows.Handle(f.Fd())
		isFile = true
	}

	if !isFile {
		// Fallback for non-file readers: blocking copy
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

		// Wait for input with 50ms timeout
		event, err := windows.WaitForSingleObject(handle, 50)
		if err != nil {
			return
		}

		switch event {
		case uint32(windows.WAIT_OBJECT_0):
			// Input is available - read it
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
		case uint32(windows.WAIT_TIMEOUT):
			// Timeout - loop back and check done channel
			continue
		default:
			// WAIT_FAILED or other error
			return
		}
	}
}
