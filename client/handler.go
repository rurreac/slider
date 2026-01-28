package client

import (
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/listener"
	"slider/pkg/session"
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

	// Accepted operations based on mode
	acceptedOps := []string{}
	if c.isListener {
		// Listener Mode: Accepts connections from Servers (Gateway/Operator)
		acceptedOps = append(acceptedOps, conf.OperationGateway, conf.OperationOperator)
	}
	if c.isBeacon {
		// Beacon Mode: Accepts connections from Beacons
		acceptedOps = append(acceptedOps, conf.OperationAgent)
	}

	// Wrap with WebSocket upgrade check for server connections
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if listener.IsSliderWebSocket(r, c.customProto, acceptedOps) {
			op := r.Header.Get("Sec-WebSocket-Operation")

			// Check if this is a Beacon connection (Only allowed in Beacon mode)
			if op == conf.OperationAgent {
				if c.isBeacon {
					c.handleBeaconConnection(w, r)
				} else {
					c.Logger.Warnf("Rejected Beacon connection in non-beacon mode")
					w.WriteHeader(http.StatusForbidden)
				}
				return
			}

			// Handle Server Connections (Only allowed in Listener mode)
			if c.isListener {
				c.handleWebSocket(w, r)
			} else {
				c.Logger.Warnf("Rejected Server connection in non-listener mode")
				w.WriteHeader(http.StatusForbidden)
			}
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

	// Inbound connection is always a listener session
	session := c.newWebSocketSession(wsConn, true)
	defer c.dropWebSocketSession(session)

	go c.newSSHClient(session)

	<-session.Disconnect
	close(session.Disconnect)
}

// getUpstreamSession returns the active session connected to the server
func (c *client) getUpstreamSession() *session.BidirectionalSession {
	if c.isListener {
		return nil
	}

	c.sessionTrackMutex.Lock()
	defer c.sessionTrackMutex.Unlock()

	// Return the first non-listener session, since this refers to the
	// outbound connection there should be only one available or none
	// if disconnected.
	for _, sess := range c.sessionTrack.Sessions {
		if !sess.GetIsListener() && sess.GetSSHClient() != nil {
			return sess
		}
	}

	return nil
}
