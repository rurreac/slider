package client

import (
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/wtemplate"
	"strings"
)

func (c *client) handleHTTPConn(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		c.handleWebSocket(w, r)
		return
	}

	var svrHeader string
	status := http.StatusNotFound
	tmpl := "Not Found"

	if c.webTemplate != "" {
		t, tErr := wtemplate.GetTemplate(c.webTemplate)
		if tErr == nil {
			svrHeader = c.webTemplate
			status = http.StatusOK
			tmpl = t
		}
	}

	w.Header().Add("server", svrHeader)

	var wErr error
	switch r.URL.Path {
	case "/health":
		_, wErr = w.Write([]byte("OK"))
	case "/":
		w.WriteHeader(status)
		_, wErr = w.Write([]byte(tmpl))
	default:
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}
	if wErr != nil {
		c.Logger.Errorf("handleClient: %v", wErr)
	}
}

func (c *client) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var upgrader = conf.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, c.httpHeaders)
	if err != nil {
		c.Logger.Errorf("Failed to upgrade client \"%s\": %v", r.Host, err)
		return
	}
	defer func() { _ = wsConn.Close() }()

	c.Logger.Debugf("Upgraded client \"%s\" HTTP connection to WebSocket.", r.RemoteAddr)

	session := c.newWebSocketSession(wsConn)
	defer c.dropWebSocketSession(session)

	session.disconnect = make(chan bool, 1)

	go c.newSSHClient(session)

	<-session.disconnect
	close(session.disconnect)
}
