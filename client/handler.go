package client

import (
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/slog"
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
		c.Logger.WithCaller().DebugWith("Received unsupported protocol", nil,
			slog.F("proto", secProto),
			slog.F("operation", secOperation))
	}

	if hErr := conf.HandleHttpRequest(w, r, &types.HttpHandler{
		TemplatePath: c.templatePath,
		ServerHeader: c.serverHeader,
		StatusCode:   c.statusCode,
		UrlRedirect:  c.urlRedirect,
		VersionOn:    c.httpVersion,
		HealthOn:     c.httpHealth,
	}); hErr != nil {
		c.Logger.WithCaller().DebugWith("Error handling HTTP request", nil,
			slog.F("err", hErr))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}

}

func (c *client) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := conf.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, c.httpHeaders)
	if err != nil {
		c.Logger.WithCaller().DebugWith("Failed to upgrade client", nil,
			slog.F("host", r.Host),
			slog.F("err", err))
		return
	}
	defer func() { _ = wsConn.Close() }()

	c.Logger.WithCaller().DebugWith("Upgraded client HTTP connection to WebSocket", nil,
		slog.F("host", r.Host),
		slog.F("remote_addr", r.RemoteAddr))

	session := c.newWebSocketSession(wsConn)
	defer c.dropWebSocketSession(session)

	session.disconnect = make(chan bool, 1)

	go c.newSSHClient(session)

	<-session.disconnect
	close(session.disconnect)
}
