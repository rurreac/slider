//go:build !windows

package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/websocket"
)

func monitorWindowResize(wsConn *websocket.Conn, done chan struct{}) {
	sigwinch := make(chan os.Signal, 1)
	signal.Notify(sigwinch, syscall.SIGWINCH)
	defer signal.Stop(sigwinch)

	for {
		select {
		case <-done:
			return
		case <-sigwinch:
			sendTermSize(wsConn)
		}
	}
}
