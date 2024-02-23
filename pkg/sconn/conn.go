package sconn

import (
	"net"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	*websocket.Conn
	buff []byte
}

func (w *wsConn) Read(p []byte) (int, error) {
	var src []byte

	if len(w.buff) > 0 {
		src = w.buff
		w.buff = nil
	} else if _, pConn, err := w.Conn.ReadMessage(); err == nil {
		src = pConn
	} else {
		return 0, err
	}

	var n int
	dl := len(p)
	if len(src) > dl {
		// Copy as many bytes as fit into "dest"
		n = copy(p, src[:dl])
		// Calculate reminder bytes and copy them into buffer
		r := src[dl:]
		w.buff = make([]byte, len(r))
		copy(w.buff, r)
	} else {
		n = copy(p, src)
	}

	return n, nil
}

func (w *wsConn) Write(p []byte) (int, error) {
	if err := w.Conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) SetDeadline(t time.Time) error {
	if err := w.SetReadDeadline(t); err != nil {
		return err
	}
	return w.SetWriteDeadline(t)
}

// WsConnToNetConn converts a websocket.Conn into a net.Conn
// Requires implementing Read, Write and SetDeadLine methods
func WsConnToNetConn(websocketConn *websocket.Conn) net.Conn {
	w := wsConn{
		Conn: websocketConn,
	}
	return &w
}
