package client

import (
	"net/http"
	"slider/pkg/listener"
	"slider/pkg/slog"
)

// buildRouter creates the HTTP router with all configured endpoints
func (c *client) buildRouter() http.Handler {
	// Get base router with common endpoints
	mux := listener.NewRouter(&listener.RouterConfig{
		TemplatePath: c.templatePath,
		ServerHeader: c.serverHeader,
		StatusCode:   c.statusCode,
		HealthOn:     c.httpHealth,
		VersionOn:    c.httpVersion,
		UrlRedirect:  c.urlRedirect,
	})

	// Accepted operations for reverse connections from servers
	acceptedOps := []string{listener.OperationServer, listener.OperationPromiscuous}

	// Wrap with WebSocket upgrade check for server connections
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if listener.IsSliderWebSocket(r, c.customProto, acceptedOps) {
			c.handleWebSocket(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (c *client) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := listener.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, c.httpHeaders)
	if err != nil {
		c.Logger.DebugWith("Failed to upgrade client",
			slog.F("host", r.Host),
			slog.F("err", err))
		return
	}
	defer func() { _ = wsConn.Close() }()

	c.Logger.DebugWith("Upgraded client HTTP connection to WebSocket",
		slog.F("host", r.Host),
		slog.F("remote_addr", r.RemoteAddr))

	session := c.newWebSocketSession(wsConn)
	defer c.dropWebSocketSession(session)

	session.disconnect = make(chan bool, 1)

	go c.newSSHClient(session)

	<-session.disconnect
	close(session.disconnect)
}
