package client

import (
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/listener"
	"slider/pkg/sconn"
	"slider/pkg/sio"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// handleBeaconConnection handles incoming connections from other agents and tunnels
// the connection to the Server as a transparent proxy
func (c *client) handleBeaconConnection(w http.ResponseWriter, r *http.Request) {
	// Upgrade to WebSocket
	upgrader := listener.DefaultWebSocketUpgrader
	wsConn, err := upgrader.Upgrade(w, r, c.httpHeaders)
	if err != nil {
		c.Logger.ErrorWith("Failed to upgrade Beacon client",
			slog.F("host", r.Host),
			slog.F("err", err))
		return
	}
	defer func() { _ = wsConn.Close() }()

	c.Logger.InfoWith("Beacon Connection Received",
		slog.F("remote_addr", wsConn.RemoteAddr().String()))

	// Find the Server session
	upstreamSess := c.getUpstreamSession()
	if upstreamSess == nil {
		c.Logger.ErrorWith("No upstream session available for tunneling",
			slog.F("remote_addr", wsConn.RemoteAddr().String()))
		return
	}
	upstreamClient := upstreamSess.GetSSHClient()
	if upstreamClient == nil {
		c.Logger.ErrorWith("Upstream session has no active SSH client",
			slog.F("session_id", upstreamSess.GetID()))
		return
	}

	// Open a Beacon channel on the Server session
	channel, reqs, err := upstreamClient.OpenChannel(conf.SSHChannelSliderBeacon, nil)
	if err != nil {
		c.Logger.ErrorWith("Failed to open Beacon channel to server",
			slog.F("err", err))
		return
	}
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(reqs)

	c.Logger.InfoWith("Beacon Tunnel Established",
		slog.F("upstream_session", upstreamSess.GetID()),
		slog.F("child_addr", wsConn.RemoteAddr().String()))

	// Wrap connection and pipe data to channel
	childConn := sconn.WsConnToNetConn(wsConn)
	tx, rx := sio.PipeWithCancel(childConn, channel)

	c.Logger.DebugWith("Beacon Tunnel Closed",
		slog.F("tx_bytes", tx),
		slog.F("rx_bytes", rx))
}
