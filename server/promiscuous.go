package server

import (
	"encoding/json"
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/sconn"
	"slider/pkg/slog"
	"slider/server/remote"
	"time"

	"golang.org/x/crypto/ssh"
)

// NewSSHClient establishes an SSH connection as a client (Promiscuous Mode)
func (s *server) NewSSHClient(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	s.DebugWith(
		"Established WebSocket connection with server (Promiscuous)",
		slog.F("session_id", session.sessionID),
		slog.F("remote_addr", netConn.RemoteAddr().String()),
	)

	// In promiscuous mode, we are the CLIENT connecting to another SERVER.
	// We need to perform the SSH handshake as a client.

	// Determine AuthMethod
	var authMethods []ssh.AuthMethod
	if s.authOn {
		// If we require auth, we should probably authenticate ourselves to the other server?
		// User requirement: "Servers authentication in a chain would be dependent of the --auth flag.
		// If the flag is not present within the server running in promiscuous mode, no authentication
		// would be required, otherwise it would require validation against the promiscous server cert jar."

		// If THIS server has --auth, it means IT expects auth.
		// But here we are connecting OUT.
		// The requirement says: "If the flag is not present within the server running in promiscuous mode,
		// no authentication would be required, otherwise it would require validation against the promiscous server cert jar."
		// This likely refers to INCOMING connections to the promiscuous server.
		// But valid for OUTGOING?
		// Just in case, let's offer our Server Key as a Public Key auth method.

		// Create a signer from our server key
		signer := s.serverKey
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	} else {
		// Use "none" auth or similar?
		// ssh.ClientConfig usually requires at least one AuthMethod.
		// "none" is implicit if we don't provide others? No, must specify.
		// Let's try "none" if no auth.
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

	cConn, newChan, reqChan, err := ssh.NewClientConn(netConn, session.wsConn.RemoteAddr().String(), sshConfig)
	if err != nil {
		s.DErrorWith("Failed to establish SSH client connection", slog.F("err", err))
		if session.notifier != nil {
			session.notifier <- err
		}
		return
	}

	// Intercept requests to handle keep-alive
	// ssh.Client by default rejects all global requests. We need to handle 'keep-alive'.
	// We will handle requests in a separate goroutine and pass nil to NewClient for requests
	// (or we could pass a pipe if we needed NewClient to see some, but currently only keep-alive matters)

	// Identify ourselves to the upstream server
	interp, iErr := interpreter.NewInterpreter()
	if iErr == nil {
		clientInfo := &conf.ClientInfo{Interpreter: interp}
		payload, _ := json.Marshal(clientInfo)
		s.DebugWith("Sending client-info to upstream server", slog.F("session_id", session.sessionID))
		ok, reply, sErr := cConn.SendRequest("client-info", true, payload)
		if sErr == nil && ok && len(reply) > 0 {
			// The server identifies itself in the reply
			var remoteInterp interpreter.Interpreter
			if mErr := json.Unmarshal(reply, &remoteInterp); mErr == nil {
				session.setInterpreter(&remoteInterp)
			}
		}
	}

	// Start KeepAlive sender
	go session.keepAlive(s.keepalive)

	// Create and configure router
	router := remote.NewRouter(s.Logger)
	session.Router = router

	// Handle incoming requests (KeepAlive from server)
	go s.handlePromiscuousRequests(session, reqChan)

	// Route channels
	go func() {
		for nc := range newChan {
			go func(nnc ssh.NewChannel) {
				if err := router.Route(nnc, session, s); err != nil {
					s.DErrorWith("Channel routing error", slog.F("err", err))
				}
			}(nc)
		}
	}()

	// Since we are consuming reqChan, we pass nil to NewClient.
	// Note: NewClient uses reqChan to handle server-initiated global requests.
	// If we consume it, NewClient won't see them. This is fine as long as we handle what we need.
	client := ssh.NewClient(cConn, nil, nil) // passing nil for channels as we handle them

	s.DebugWith("SSH Client Connection Established", slog.F("session_id", session.sessionID))

	// Store the connection
	session.setSSHClient(client)

	if session.notifier != nil {
		session.notifier <- nil
	}

	// Block until connection closes
	_ = client.Wait()
}

// RemoteSession defines the session info returned by RPC
type RemoteSession struct {
	ID                int64   `json:"id"`
	ServerFingerprint string  `json:"server_fingerprint"`
	User              string  `json:"user"`
	Host              string  `json:"host"`
	System            string  `json:"system"`
	Arch              string  `json:"arch"`
	IsListener        bool    `json:"is_listener"`
	ConnectionAddr    string  `json:"connection_addr"`
	Path              []int64 `json:"path"`
}

// GetRemoteSessionsRequest defines the payload for slider-sessions request
type GetRemoteSessionsRequest struct {
	Visited []string `json:"visited"`
}

// GetRemoteSessions fetches sessions from the connected promiscuous server
func (session *Session) GetRemoteSessions(visited []string) ([]RemoteSession, error) {
	session.sessionMutex.Lock()
	client := session.sshClient
	session.sessionMutex.Unlock()

	if client == nil {
		return nil, fmt.Errorf("no active ssh client connection")
	}

	req := GetRemoteSessionsRequest{
		Visited: visited,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send a specific request to the server to get sessions
	ok, resPayload, err := client.SendRequest("slider-sessions", true, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send slider-sessions request: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("server rejected slider-sessions request")
	}

	var sessions []RemoteSession
	if err := json.Unmarshal(resPayload, &sessions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sessions: %w", err)
	}

	return sessions, nil
}

// HandleSessionsRequest processes incoming slider-sessions requests
func (s *server) HandleSessionsRequest(req *ssh.Request, currentSession *Session) (err error) {
	// Panic Recovery
	defer func() {
		if r := recover(); r != nil {
			s.ErrorWith("Panic in HandleSessionsRequest", slog.F("panic", r))
			err = fmt.Errorf("internal server error")
		}
	}()

	var request GetRemoteSessionsRequest
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &request); err != nil {
			return fmt.Errorf("failed to unmarshal request: %w", err)
		}
	}

	// Loop detection
	currentIdentity := fmt.Sprintf("%s:%d", s.fingerprint, s.port)
	for _, visited := range request.Visited {
		if visited == currentIdentity {
			s.WarnWith("Loop/Self-connection detected in session listing", slog.F("identity", currentIdentity))
			return fmt.Errorf("loop detected: server %s is already in the chain", currentIdentity)
		}
	}
	// Add self to visited
	visitedChain := append(request.Visited, currentIdentity)

	// Gather sessions
	var sessions []RemoteSession

	// 1. Local sessions
	s.sessionTrackMutex.Lock()
	s.DebugWith("Processing HandleSessionsRequest", slog.F("total_sessions", len(s.sessionTrack.Sessions)))
	for _, sess := range s.sessionTrack.Sessions {
		// Skip the session that is asking for the list (the caller)
		if sess.sessionID == currentSession.sessionID {
			continue
		}

		s.DebugWith("Checking session for list", slog.F("id", sess.sessionID), slog.F("is_client", sess.clientInterpreter != nil), slog.F("is_promiscuous", sess.sshClient != nil))
		// Identify user/host/system/arch
		user := "slider"
		host := sess.hostIP
		system := "unknown"
		arch := "unknown"
		if sess.clientInterpreter != nil {
			user = sess.clientInterpreter.User
			host = sess.clientInterpreter.Hostname
			system = sess.clientInterpreter.System
			arch = sess.clientInterpreter.Arch
		}

		sessions = append(sessions, RemoteSession{
			ID:                sess.sessionID,
			ServerFingerprint: s.fingerprint,
			User:              user,
			Host:              host,
			System:            system,
			Arch:              arch,
			IsListener:        sess.isListener,
			ConnectionAddr:    sess.wsConn.RemoteAddr().String(),
		})
	}

	promiscuousClients := make([]*Session, 0)
	for _, sess := range s.sessionTrack.Sessions {
		if sess.sshClient != nil {
			promiscuousClients = append(promiscuousClients, sess)
		}
	}
	s.sessionTrackMutex.Unlock()

	// 2. Remote sessions (recursive)
	for _, clientSess := range promiscuousClients {
		remoteSessions, err := clientSess.GetRemoteSessions(visitedChain)
		if err != nil {
			s.WarnWith("Failed to fetch remote sessions", slog.F("err", err))
			continue
		}
		// Prepend clientSess.sessionID to Path
		for i := range remoteSessions {
			remoteSessions[i].Path = append([]int64{clientSess.sessionID}, remoteSessions[i].Path...)
		}
		sessions = append(sessions, remoteSessions...)
	}

	// Marshal response
	payload, err := json.Marshal(sessions)
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}

	return req.Reply(true, payload)
}

// handlePromiscuousRequests handles global requests from the upstream server
func (s *server) handlePromiscuousRequests(session *Session, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "keep-alive":
			_ = session.replyConnRequest(req, true, []byte("pong"))
		case "client-info":
			ci := &conf.ClientInfo{}
			if jErr := json.Unmarshal(req.Payload, ci); jErr == nil {
				session.setInterpreter(ci.Interpreter)
			}
			_ = session.replyConnRequest(req, true, nil)
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
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
	var upstreams []*Session
	for _, sess := range s.sessionTrack.Sessions {
		if sess.sshClient != nil {
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
		go func(sess *Session) {
			sess.sessionMutex.Lock()
			client := sess.sshClient
			sess.sessionMutex.Unlock()
			if client == nil {
				return
			}
			_, _, _ = client.SendRequest("slider-event", false, payload)
		}(up)
	}
}

// HandleEventRequest processes incoming slider-event requests
func (s *server) HandleEventRequest(req *ssh.Request, fromSession *Session) error {
	var event EventRequest
	if err := json.Unmarshal(req.Payload, &event); err != nil {
		return fmt.Errorf("failed to unmarshal event: %w", err)
	}

	s.InfoWith("Received Upstream Event",
		slog.F("type", event.Type),
		slog.F("remote_session_id", event.SessionID),
		slog.F("via_session", fromSession.sessionID),
	)

	return nil
}
