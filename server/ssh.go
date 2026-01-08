package server

import (
	"strconv"

	"slider/pkg/remote"
	"slider/pkg/sconn"
	pkgsession "slider/pkg/session"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

func (s *server) NewSSHServer(session *pkgsession.BidirectionalSession) {
	netConn := sconn.WsConnToNetConn(session.GetWebSocketConn())

	s.DebugWith(
		"Established WebSocket connection with client",
		slog.F("session_id", session.GetID()),
		slog.F("remote_addr", netConn.RemoteAddr().String()),
	)

	var sshServerConn *ssh.ServerConn
	var newChan <-chan ssh.NewChannel
	var reqChan <-chan *ssh.Request
	var err error

	sshConf := session.GetSSHConfig()
	// Disable authentication for listener sessions
	if session.GetIsListener() {
		sshConf.NoClientAuth = true
	}

	sshServerConn, newChan, reqChan, err = ssh.NewServerConn(netConn, sshConf)
	if err != nil {
		s.DErrorWith("Failed to create SSH server", slog.F("err", err))
		if session.GetNotifier() != nil {
			session.GetNotifier() <- err
		}
		return
	}
	session.SetSSHServerConn(sshServerConn)

	// Update endpoint instances with the SSH connection
	if session.GetShellInstance() != nil {
		session.GetShellInstance().SetSSHConn(sshServerConn)
	}
	if session.GetSocksInstance() != nil {
		session.GetSocksInstance().SetSSHConn(sshServerConn)
	}
	if session.GetSSHInstance() != nil {
		session.GetSSHInstance().SetSSHConn(sshServerConn)
	}

	// If authentication was enabled and not a listener session, save the client certificate info
	if s.authOn && !session.GetIsListener() {
		if certID, cErr := strconv.Atoi(sshServerConn.Permissions.Extensions["cert_id"]); cErr == nil {
			session.SetCertInfo(
				int64(certID),
				sshServerConn.Permissions.Extensions["fingerprint"],
			)
		}

	}

	s.DebugWith(
		"Upgraded Websocket transport to SSH Connection",
		slog.F("session_id", session.GetID()),
		slog.F("host", session.GetSSHServerConn().RemoteAddr().String()),
		slog.F("client_version", session.GetSSHServerConn().ClientVersion()),
	)

	if session.GetNotifier() != nil {
		session.GetNotifier() <- nil
	}

	// Handle Keep Alive
	go session.KeepAlive(s.keepalive)

	// Inject application server for all sessions to provide access to local interpreter and state
	// Presence of these components enables proper local process execution and multi-hop features
	session.SetApplicationServer(s)

	if s.promiscuous {
		// Create and configure application router for slider-connect channels
		appRouter := remote.NewRouter(s.Logger)
		appRouter.RegisterHandler("slider-connect", remote.HandleSliderConnect)
		session.SetRouter(appRouter)
	}

	// Use centralized channel routing
	// Session handles all standard SSH protocol channels (shell, exec, sftp, etc.)
	// Application-specific channels (slider-connect) are delegated to injected router
	go session.HandleIncomingChannels(newChan)

	// Use centralized request handling
	// Session handles common protocol requests (keep-alive, tcpip-forward)
	// Application-specific requests (slider-*, client-info, etc.) are delegated to injected handler
	go session.HandleIncomingRequests(reqChan)

	// Block until connection closes
	_ = sshServerConn.Wait()
}
