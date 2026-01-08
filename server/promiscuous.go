package server

import (
	"encoding/json"
	"time"

	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/sconn"
	"slider/pkg/session"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// NewSSHClient establishes an SSH connection as a client (Promiscuous Mode)
func (s *server) NewSSHClient(sess *session.BidirectionalSession) {
	netConn := sconn.WsConnToNetConn(sess.GetWebSocketConn())

	s.DebugWith(
		"Established WebSocket connection with server (Promiscuous)",
		slog.F("session_id", sess.GetID()),
		slog.F("remote_addr", netConn.RemoteAddr().String()),
	)

	// Determine auth method for outgoing connection
	var authMethods []ssh.AuthMethod
	if s.authOn {
		// When --auth is enabled, authenticate using server's public key
		authMethods = append(authMethods, ssh.PublicKeys(s.serverKey))
	} else {
		// No authentication required; use keyboard-interactive fallback for compatibility
		authMethods = append(authMethods, ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
			return nil, nil
		}))
	}

	sshConfig := &ssh.ClientConfig{
		User:            "slider-server", // Identify as a server
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // TODO: Verify host key if needed?
		ClientVersion:   "SSH-slider-server-client",
	}

	cConn, newChan, reqChan, err := ssh.NewClientConn(netConn, sess.GetWebSocketConn().RemoteAddr().String(), sshConfig)
	if err != nil {
		s.DErrorWith("Failed to establish SSH client connection", slog.F("err", err))
		if sess.GetNotifier() != nil {
			sess.GetNotifier() <- err
		}
		return
	}

	// Identify ourselves to the upstream server
	interp, iErr := interpreter.NewInterpreter()
	if iErr == nil {
		clientInfo := &conf.ClientInfo{
			Interpreter: interp,
		}
		payload, _ := json.Marshal(clientInfo)
		s.DebugWith("Sending client-info to upstream server", slog.F("session_id", sess.GetID()))
		ok, reply, sErr := cConn.SendRequest("client-info", true, payload)
		if sErr == nil && ok && len(reply) > 0 {
			// The server identifies itself in the reply
			var ciAnswer conf.ClientInfo
			if mErr := json.Unmarshal(reply, &ciAnswer); mErr == nil {
				if ciAnswer.Interpreter != nil {
					sess.SetInterpreter(ciAnswer.Interpreter)
				}
			}
		}
	}

	// Start KeepAlive sender
	go sess.KeepAlive(s.keepalive)

	// Inject application server for local interpreter and state access
	sess.SetApplicationServer(s)

	// Note: For upstream connections (OperatorRole connecting TO another server),
	// we do NOT inject application-specific router by default. This is an outgoing client connection,
	// and slider-* requests/channels are typically handled on the server side of the connection.
	// The centralized handlers in the session package will now have access to the local server
	// info via the injected applicationServer.

	// Use centralized request handling
	// Session handles common protocol requests (keep-alive, tcpip-forward)
	// Application-specific requests (client-info, shutdown) are delegated to injected handler
	go sess.HandleIncomingRequests(reqChan)

	// Use centralized channel routing
	// Session handles all standard SSH protocol channels (shell, exec, sftp, etc.)
	// Application-specific channels (slider-connect) are delegated to injected router
	go sess.HandleIncomingChannels(newChan)

	// Pass nil for channels since we consume reqChan directly
	client := ssh.NewClient(cConn, nil, nil)

	s.DebugWith("SSH Client Connection Established", slog.F("session_id", sess.GetID()))

	// Store the connection
	sess.SetSSHClient(client)
	// Update endpoint instances with the SSH client connection
	// (they were initialized with nil when the session was first created)
	if sess.GetShellInstance() != nil {
		sess.GetShellInstance().SetSSHConn(client)
	}
	if sess.GetSocksInstance() != nil {
		sess.GetSocksInstance().SetSSHConn(client)
	}
	if sess.GetSSHInstance() != nil {
		sess.GetSSHInstance().SetSSHConn(client)
	}

	if sess.GetNotifier() != nil {
		sess.GetNotifier() <- nil
	}

	// Block until connection closes
	_ = client.Wait()
}

// EventRequest defines the payload for slider-event request
type EventRequest struct {
	Type      string `json:"type"`       // e.g., "disconnect"
	SessionID int64  `json:"session_id"` // Local ID that caused the event
	Timestamp int64  `json:"timestamp"`
}

// NotifyUpstreamDisconnect sends a disconnect event to all connected upstream servers
func (s *server) NotifyUpstreamDisconnect(id int64) {
	s.sessionTrackMutex.Lock()
	var upstreams []*session.BidirectionalSession
	for _, sess := range s.sessionTrack.Sessions {
		if sess.GetSSHClient() != nil {
			upstreams = append(upstreams, sess)
		}
	}
	s.sessionTrackMutex.Unlock()

	req := EventRequest{
		Type:      "disconnect",
		SessionID: id,
		Timestamp: time.Now().Unix(),
	}

	payload, _ := json.Marshal(req)

	for _, up := range upstreams {
		go func(sess *session.BidirectionalSession) {
			client := sess.GetSSHClient()
			if client == nil {
				return
			}
			_, _, _ = client.SendRequest("slider-event", false, payload)
		}(up)
	}
}
