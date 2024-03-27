package client

import (
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"strings"
)

func (c *client) handleHTTPConn(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		c.handleWebSocket(w, r)
		return
	}
	var err error
	switch r.URL.Path {
	case "/health":
		_, err = w.Write([]byte("OK"))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, err = w.Write([]byte("Not Found"))
	}
	if err != nil {
		c.Errorf("handleClient: %v", err)
	}
}

func (c *client) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var upgrader = conf.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, c.httpHeaders)
	if err != nil {
		c.Errorf("Failed to upgrade client \"%s\": %v", r.Host, err)
		return
	}
	defer func() { _ = wsConn.Close() }()

	c.Debugf("Upgraded client \"%s\" HTTP connection to WebSocket.", r.RemoteAddr)

	session := c.newWebSocketSession(wsConn)
	defer c.dropWebSocketSession(session)

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		session.Fatalf("Interpreter not supported - %v", iErr)
	}
	session.addInterpreter(i)

	session.disconnect = make(chan bool, 1)

	go c.newSSHClient(session)

	<-session.disconnect
	close(session.disconnect)
}
