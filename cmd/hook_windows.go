//go:build windows

package cmd

import (
	"github.com/gorilla/websocket"
)

func monitorWindowResize(_ *websocket.Conn, done chan struct{}) {
	// Windows doesn't support SIGWINCH in the same way.
	// We just wait for done channel to close.
	<-done
}
