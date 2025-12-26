//go:build windows

package sio

import (
	"io"
	"os"

	"golang.org/x/sys/windows"
)

// CopyStdinCancellable copies from stdin to dst until done is closed.
// Uses WaitForSingleObject with timeout to make the copy cancellable.
// Returns when either: done channel is closed, stdin returns EOF, or write to dst fails.
func CopyStdinCancellable(dst io.Writer, done <-chan struct{}) {
	handle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		// Fallback: blocking copy (user will need to press a key to return)
		go func() {
			<-done
		}()
		_, _ = io.Copy(dst, os.Stdin)
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
		case uint32(windows.WAIT_TIMEOUT):
			// Timeout - loop back and check done channel
			continue
		default:
			// WAIT_FAILED or other error
			return
		}
	}
}
