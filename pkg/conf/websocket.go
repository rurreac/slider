package conf

import (
	"github.com/gorilla/websocket"
)

var DefaultWebSocketDialer = &websocket.Dialer{
	NetDial:          nil,
	HandshakeTimeout: Timeout,
	Subprotocols:     nil,
	// Use Default Buffer Size
	ReadBufferSize:  0,
	WriteBufferSize: 0,
}

var DefaultWebSocketUpgrader = &websocket.Upgrader{
	HandshakeTimeout: Timeout,
}
