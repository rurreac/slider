//go:build !windows

package server

import (
	"net"
	"os"
	"os/signal"
	"syscall"
)

// CaptureInterrupts Capture interrupt signals and close the connection cause this terminal doesn't know how to handle them
func (ic *InteractiveConsole) CaptureInterrupts(conn net.Conn) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	for range sig {
		// Stop capture
		signal.Stop(sig)
		close(sig)
		if cErr := conn.Close(); cErr != nil {
			ic.ui.PrintDebug("Failed to close Shell connection - %v", cErr)
		}
	}
}
