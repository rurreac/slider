package client

import (
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/types"
	"strings"
)

func (c *client) handleHTTPConn(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		proto := conf.HttpVersionResponse.ProtoVersion
		if c.customProto != conf.HttpVersionResponse.ProtoVersion {
			proto = c.customProto
		}
		secProto := r.Header.Get("Sec-WebSocket-Protocol")
		secOperation := r.Header.Get("Sec-WebSocket-Operation")
		if secProto == proto && secOperation == "server" {
			c.handleWebSocket(w, r)
			return
		}
		c.Logger.Debugf("Received unsupported protocol: %s, and operation: %s", secProto, secOperation)
	}

	if hErr := conf.HandleHttpRequest(w, r, &types.HttpHandler{
		TemplatePath: c.templatePath,
		ServerHeader: c.serverHeader,
		StatusCode:   c.statusCode,
		UrlRedirect:  c.urlRedirect,
		VersionOn:    c.httpVersion,
		HealthOn:     c.httpHealth,
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
