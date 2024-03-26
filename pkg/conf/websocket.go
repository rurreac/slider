package conf

import (
	"github.com/gorilla/websocket"
)

func NewWebSocketDialer() *websocket.Dialer {
	return &websocket.Dialer{
		NetDial:          nil,
		HandshakeTimeout: Timeout,
		Subprotocols:     nil,
		// Use Default Buffer Size
		ReadBufferSize:  0,
		WriteBufferSize: 0,
	}
}

func NewWebSocketUpgrader() *websocket.Upgrader {
	return &websocket.Upgrader{
		HandshakeTimeout: Timeout,
	}
}
