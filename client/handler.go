package client

import (
	"net/http"
	"slider/pkg/conf"
	"strings"
)

func (c *client) handleHTTPConn(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		if r.Header.Get("Sec-WebSocket-Protocol") == conf.HttpVersionResponse.ProtoVersion {
			c.handleWebSocket(w, r)
			return
		}
	}

	if hErr := conf.HandleHttpRequest(w, r, &conf.HttpHandler{
		TemplatePath: c.templatePath,
		ServerHeader: c.serverHeader,
		StatusCode:   c.statusCode,
		UrlRedirect:  c.urlRedirect,
		ShowVersion:  c.showVersion,
	}); hErr != nil {
		c.Logger.Errorf("Error handling HTTP request: %v", hErr)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}

}

func (c *client) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := conf.DefaultWebSocketUpgrader

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
