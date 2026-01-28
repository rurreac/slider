package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"time"

	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// handleSSHRequests processes incoming SSH requests (PTY, window-change, env)
// This is called as a goroutine to handle requests asynchronously
func (s *BidirectionalSession) handleSSHRequests(
	requests <-chan *ssh.Request,
	winChange chan<- []byte,
	envChange chan<- []byte,
) {
	defer close(winChange)
	defer close(envChange)
	for req := range requests {
		ok := false

		if req.Type != "env" {
			s.logger.DebugWith("SSH Request",
				slog.F("session_id", s.sessionID),
				slog.F("request_type", req.Type),
				slog.F("payload", req.Payload))
		}

		switch req.Type {
		case "env":
			// Environment variable setting
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			envChange <- req.Payload

		case "window-change":
			// Terminal window size change
			if s.peerBaseInfo.PtyOn {
				ok = true
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			winChange <- req.Payload

		case "pty-req":
			// PTY request - typically handled before shell/exec
			// Standard SSH clients send dimensions here
			var ptyReq types.PtyRequest
			if err := ssh.Unmarshal(req.Payload, &ptyReq); err != nil {
				s.logger.ErrorWith("Failed to unmarshal pty-req",
					slog.F("session_id", s.sessionID),
					slog.F("err", err))
				ok = false
			} else {
				s.logger.DebugWith("Received pty-req",
					slog.F("session_id", s.sessionID),
					slog.F("term", ptyReq.TermEnvVar),
					slog.F("cols", ptyReq.TermWidthCols),
					slog.F("rows", ptyReq.TermHeightRows))

				s.SetInitTermSize(types.TermDimensions{
					Width:  ptyReq.TermWidthCols,
					Height: ptyReq.TermHeightRows,
				})
				ok = true
			}

			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}

		default:
			s.logger.WarnWith("Rejected SSH request type",
				slog.F("session_id", s.sessionID),
				slog.F("request_type", req.Type))
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		}
	}
}

// ========================================
// Global Request Routing
// ========================================

// HandleIncomingRequests processes SSH global requests
// Handles common protocol requests and delegates application-specific ones
func (s *BidirectionalSession) HandleIncomingRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		go s.routeRequest(req)
	}
}

// routeRequest routes a global request to the appropriate handler
func (s *BidirectionalSession) routeRequest(req *ssh.Request) {
	s.logger.DebugWith("Routing request",
		slog.F("session_id", s.sessionID),
		slog.F("type", req.Type),
		slog.F("role", s.role.String()))

	switch req.Type {
	// ========================================
	// Protocol-level requests (common SSH)
	// ========================================
	case "keep-alive":
		s.handleKeepAlive(req)

	case "tcpip-forward":
		if s.role.IsAgent() || s.role.IsGateway() {
			go s.handleTcpIpForward(req)
		} else {
			s.rejectRequest(req, "tcpip-forward not supported in this role")
		}

	case "cancel-tcpip-forward":
		if s.role.IsAgent() || s.role.IsGateway() {
			s.handleCancelTcpIpForward(req)
		} else {
			s.rejectRequest(req, "cancel-tcpip-forward not supported in this role")
		}

	// ========================================
	// Application-specific requests
	// ========================================
	case "client-info":
		s.handleClientInfo(req)

	case "window-size":
		// All connections where someone might want a terminal size
		s.handleWindowSize(req)

	case "slider-sessions":
		// Only sessions with a router/applicationServer handle this (Gateway/Agent in gateway mode)
		if (s.role.IsGateway() || s.role.IsAgent()) && s.applicationServer != nil {
			s.handleSliderSessions(req)
		} else {
			s.rejectRequest(req, "slider-sessions not supported in this configuration")
		}

	case "slider-forward-request":
		// Only sessions with a router/applicationServer handle this (Gateway/Agent in gateway mode)
		if (s.role.IsGateway() || s.role.IsAgent()) && s.applicationServer != nil {
			s.handleSliderForwardRequest(req)
		} else {
			s.rejectRequest(req, "slider-forward-request not supported in this configuration")
		}

	case "slider-event":
		// Only sessions with a router/applicationServer handle this (Gateway/Agent in gateway mode)
		if (s.role.IsGateway() || s.role.IsAgent()) && s.applicationServer != nil {
			s.handleSliderEvent(req)
		} else {
			s.rejectRequest(req, "slider-event not supported in this configuration")
		}

	case "shutdown":
		s.handleShutdown(req)

	default:
		// Delegate to application-specific handler if injected (for backward compatibility)
		if s.requestHandler != nil {
			if s.requestHandler.HandleRequest(req, s) {
				return
			}
		}

		// Unknown request
		s.logger.DebugWith("Received unknown request type",
			slog.F("session_id", s.sessionID),
			slog.F("request_type", req.Type))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
	}
}

// rejectRequest rejects a request with a warning message
func (s *BidirectionalSession) rejectRequest(req *ssh.Request, reason string) {
	s.logger.WarnWith(reason,
		slog.F("session_id", s.sessionID),
		slog.F("request_type", req.Type),
		slog.F("role", s.role.String()))
	if req.WantReply {
		_ = req.Reply(false, nil)
	}
}

// ========================================
// Request Handlers
// ========================================

// handleKeepAlive handles keep-alive requests (common to all roles)
func (s *BidirectionalSession) handleKeepAlive(req *ssh.Request) {
	s.logger.DebugWith("Received keep-alive request",
		slog.F("session_id", s.sessionID))

	if err := s.ReplyConnRequest(req, true, []byte("pong")); err != nil {
		s.logger.ErrorWith("Error sending keep-alive reply",
			slog.F("session_id", s.sessionID),
			slog.F("request_type", req.Type),
			slog.F("err", err))
	}
}

// handleTcpIpForward handles tcpip-forward requests (reverse port forwarding)
// This is used by AgentRole and GatewayRole to set up reverse port forwarding (target offering fwd)
func (s *BidirectionalSession) handleTcpIpForward(req *ssh.Request) {
	tcpIpForward := &types.CustomTcpIpFwdRequest{}
	if uErr := json.Unmarshal(req.Payload, tcpIpForward); uErr != nil {
		s.logger.ErrorWith("Failed to unmarshal TcpIpFwdRequest request",
			slog.F("session_id", s.sessionID),
			slog.F("err", uErr))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	fwdAddress := fmt.Sprintf("%s:%d", tcpIpForward.BindAddress, tcpIpForward.BindPort)
	listen, err := net.Listen("tcp", fwdAddress)
	if err != nil {
		s.logger.ErrorWith("Failed to start reverse port forward listener",
			slog.F("session_id", s.sessionID),
			slog.F("fwd_address", fwdAddress),
			slog.F("err", err))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// We may have asked to bind to port 0, we want it resolved, saved and send back
	finalBindPort := listen.Addr().(*net.TCPAddr).Port
	s.logger.DebugWith("Reverse Port Forward request binding",
		slog.F("session_id", s.sessionID),
		slog.F("bind_address", tcpIpForward.BindAddress),
		slog.F("bind_port", tcpIpForward.BindPort),
		slog.F("fwd_address", fwdAddress),
		slog.F("fwd_port", finalBindPort))

	// Answer when we know if we can create a listener and the final bound port
	if req.WantReply {
		dataBytes := make([]byte, 0)
		if tcpIpForward.BindPort == 0 {
			// If the port was 0, we need to send the final bound port
			data := types.TcpIpReqSuccess{BoundPort: uint32(finalBindPort)}
			dataBytes = ssh.Marshal(data)
		}
		_ = req.Reply(true, dataBytes)
	}

	// Override the structure with the final bound port
	tcpIpForward.BindPort = uint32(finalBindPort)

	stopChan := make(chan bool, 1)
	if err := s.AddReversePortForward(tcpIpForward.BindPort, tcpIpForward.BindAddress, stopChan); err != nil {
		s.logger.ErrorWith("Failed to add reverse port forward",
			slog.F("session_id", s.sessionID),
			slog.F("bind_port", tcpIpForward.BindPort),
			slog.F("err", err))
		_ = listen.Close()
		return
	}

	defer func() {
		_ = listen.Close()
		_ = s.RemoveReversePortForward(tcpIpForward.BindPort)
	}()

	for {
		select {
		case <-stopChan:
			return
		default:
			// Proceed
		}

		// Set a timeout to force checking the stop signal regularly
		_ = listen.(*net.TCPListener).SetDeadline(time.Now().Add(conf.Timeout))
		conn, lErr := listen.Accept()
		if lErr != nil {
			// Discard timeout errors
			var netErr net.Error
			if errors.As(lErr, &netErr) && netErr.Timeout() {
				continue
			}

			s.logger.DebugWith("Error accepting connection on reverse port",
				slog.F("session_id", s.sessionID),
				slog.F("bind_port", tcpIpForward.BindPort),
				slog.F("err", lErr))
			return
		}

		go func() {
			srcAddr := conn.RemoteAddr().(*net.TCPAddr)

			// For SSH forwards: use bind address/port (forwarded back to SSH client)
			dstHost := tcpIpForward.BindAddress
			dstPort := tcpIpForward.BindPort
			// For Slider forwards: use forward destination address/port
			if !tcpIpForward.IsSshConn {
				dstHost = tcpIpForward.FwdHost
				dstPort = tcpIpForward.FwdPort
			}

			payload := &types.CustomTcpIpChannelMsg{
				IsSshConn: tcpIpForward.IsSshConn,
				TcpIpChannelMsg: &types.TcpIpChannelMsg{
					DstHost: dstHost,
					DstPort: dstPort,
					SrcHost: srcAddr.IP.String(),
					SrcPort: uint32(srcAddr.Port),
				},
			}
			customMsgBytes, mErr := json.Marshal(payload)
			if mErr != nil {
				s.logger.DebugWith("Failed to marshal custom message",
					slog.F("session_id", s.sessionID),
					slog.F("bind_port", tcpIpForward.BindPort),
					slog.F("err", mErr))
				return
			}

			// Start a "forwarded-tcpip" channel, circling back to the remote
			channel, reqs, oErr := s.GetSSHConn().OpenChannel("forwarded-tcpip", customMsgBytes)
			if oErr != nil {
				s.logger.DebugWith("Failed to open forwarded-tcpip channel",
					slog.F("session_id", s.sessionID),
					slog.F("err", oErr))
				return
			}
			defer func() { _ = channel.Close() }()
			go ssh.DiscardRequests(reqs)

			_, _ = sio.PipeWithCancel(conn, channel)

			s.logger.DebugWith("Completed request to remote",
				slog.F("session_id", s.sessionID),
				slog.F("bind_address", tcpIpForward.BindAddress),
				slog.F("bind_port", tcpIpForward.BindPort),
				slog.F("src_addr", srcAddr.IP.String()),
				slog.F("src_port", srcAddr.Port))
		}()
	}
}

// handleCancelTcpIpForward handles cancel-tcpip-forward requests
// This is used by AgentRole and GatewayRole to cancel reverse port forwarding
func (s *BidirectionalSession) handleCancelTcpIpForward(req *ssh.Request) {
	ok := false
	tcpIpForward := &types.TcpIpFwdRequest{}
	if uErr := ssh.Unmarshal(req.Payload, tcpIpForward); uErr == nil {
		revPortFwds := s.GetReversePortForwards()
		if pfc, found := revPortFwds[tcpIpForward.BindPort]; found {
			if pfc.BindAddress == tcpIpForward.BindAddress {
				pfc.StopChan <- true
				ok = true
				s.logger.DebugWith("Cancelled reverse port forward",
					slog.F("session_id", s.sessionID),
					slog.F("bind_address", tcpIpForward.BindAddress),
					slog.F("bind_port", tcpIpForward.BindPort))
			}
		}
	}
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

// ========================================
// Application-specific Request Handlers
// ========================================

// handleClientInfo handles client-info requests (all roles)
func (s *BidirectionalSession) handleClientInfo(req *ssh.Request) {
	ci := &interpreter.Info{}
	if jErr := json.Unmarshal(req.Payload, ci); jErr != nil {
		s.logger.DErrorWith("Failed to parse Client Info",
			slog.F("session_id", s.sessionID),
			slog.F("err", jErr))
		_ = s.ReplyConnRequest(req, true, nil)
		return
	}

	// Store session info from peer
	s.SetPeerInfo(ci.BaseInfo)
	// Store peer's identity if provided
	if ci.Identity != "" {
		s.SetPeerIdentity(ci.Identity)
	}

	// Reply with server info for identification
	if s.applicationServer != nil {
		// Get server info from application server
		if serverInfo := s.applicationServer.GetServerInterpreter(); serverInfo != nil {
			replyInfo := &interpreter.Info{
				BaseInfo: serverInfo.BaseInfo,
				Identity: s.applicationServer.GetServerIdentity(), // Include our identity
			}
			interpreterPayload, jErr := json.Marshal(replyInfo)
			if jErr != nil {
				s.logger.DErrorWith("Error marshaling Server Info",
					slog.F("session_id", s.sessionID),
					slog.F("err", jErr))
				_ = s.ReplyConnRequest(req, true, nil)
			} else {
				_ = s.ReplyConnRequest(req, true, interpreterPayload)
			}
			return
		}
	}
	_ = s.ReplyConnRequest(req, true, nil)
}

// handleWindowSize handles window-size requests (server roles only)
func (s *BidirectionalSession) handleWindowSize(req *ssh.Request) {
	// Get terminal size from stdout (cross-platform compatible)
	width, height, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil {
		s.logger.Errorf("Failed to obtain terminal size")
	}
	tSize := types.TermDimensions{
		Height: uint32(height),
		Width:  uint32(width),
	}
	payload, _ := json.Marshal(tSize)
	_ = s.ReplyConnRequest(req, true, payload)
}

// handleSliderSessions handles slider-sessions requests (gateway servers only)
// Gathers all local and remote sessions and returns them to the requester
func (s *BidirectionalSession) handleSliderSessions(req *ssh.Request) {
	if s.applicationServer == nil {
		s.logger.ErrorWith("Application server not set",
			slog.F("session_id", s.sessionID))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// Panic recovery
	defer func() {
		if r := recover(); r != nil {
			s.logger.ErrorWith("Panic in handleSliderSessions", slog.F("panic", r))
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()

	var request GetRemoteSessionsRequest
	if len(req.Payload) > 0 {
		if err := json.Unmarshal(req.Payload, &request); err != nil {
			s.logger.DErrorWith("Failed to unmarshal request",
				slog.F("session_id", s.sessionID),
				slog.F("err", err))
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}
	}

	// Loop detection using server identity
	currentIdentity := s.applicationServer.GetServerIdentity()
	if slices.Contains(request.Visited, currentIdentity) {
		s.logger.WarnWith("Loop/Self-connection detected in session listing",
			slog.F("session_id", s.sessionID),
			slog.F("identity", currentIdentity))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	// Add self to visited
	visitedChain := append(request.Visited, currentIdentity)

	// Gather sessions
	var sessions []RemoteSession
	fingerprint := s.applicationServer.GetFingerprint()

	// Local sessions from server registry
	localSessions := s.applicationServer.GetAllSessions()
	s.logger.DebugWith("Processing slider-sessions request",
		slog.F("session_id", s.sessionID),
		slog.F("total_sessions", len(localSessions)))

	gatewayClients := make([]*BidirectionalSession, 0)
	for _, sess := range localSessions {
		// Skip the session that is asking for the list (the caller)
		if sess.GetID() == s.sessionID {
			continue
		}

		s.logger.DebugWith("Checking session for list",
			slog.F("id", sess.GetID()),
			slog.F("is_client", sess.GetPeerInfo().User != ""),
			slog.F("is_gateway", sess.GetSSHClient() != nil))

		// Get the current SFTP working directory if available
		workingDir := sess.GetSftpWorkingDir()

		// Get connection address
		connectionAddr := ""
		if addr := sess.GetRemoteAddr(); addr != nil {
			connectionAddr = addr.String()
		}

		sessions = append(sessions, RemoteSession{
			ID:                sess.GetID(),
			ParentSessionID:   sess.GetParentSessionID(), // Track parent for beacon chains
			ServerFingerprint: fingerprint,
			BaseInfo:          sess.GetPeerInfo(),
			Role:              sess.GetPeerRole().String(),
			WorkingDir:        workingDir,
			IsConnector:       sess.GetRole().IsConnector(),
			IsGateway:         sess.GetIsGateway(),
			ConnectionAddr:    connectionAddr,
		})

		// Only query sessions that have an SSH client for remote sessions
		if sess.GetSSHClient() != nil {
			gatewayClients = append(gatewayClients, sess)
		}
	}

	// Remote sessions (recursive)
	for _, clientSess := range gatewayClients {
		remoteSessions, err := clientSess.GetRemoteSessions(visitedChain)
		if err != nil {
			s.logger.WarnWith("Failed to fetch remote sessions",
				slog.F("session_id", s.sessionID),
				slog.F("err", err))
			continue
		}
		// Prepend clientSess.GetID() to Path
		for i := range remoteSessions {
			remoteSessions[i].Path = append([]int64{clientSess.GetID()}, remoteSessions[i].Path...)
		}
		sessions = append(sessions, remoteSessions...)
	}

	// Marshal and send response
	payload, err := json.Marshal(sessions)
	if err != nil {
		s.logger.DErrorWith("Failed to marshal sessions response",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	if req.WantReply {
		_ = req.Reply(true, payload)
	}
}

// handleSliderForwardRequest handles slider-forward-request requests (gateway servers only)
// Routes forwarded requests through the mesh to their target session
func (s *BidirectionalSession) handleSliderForwardRequest(req *ssh.Request) {
	if s.applicationServer == nil {
		s.logger.ErrorWith("Application server not set",
			slog.F("session_id", s.sessionID))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	var payload types.ForwardRequestPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		s.logger.DErrorWith("Failed to unmarshal forward payload",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return
	}

	target := payload.Target

	// Parse path to find next hop
	// Path format: [id1, id2, ...]
	if len(target) == 0 {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		s.logger.DErrorWith("Empty target path in forward request",
			slog.F("session_id", s.sessionID))
		return
	}

	nextID := int(target[0])

	// Lookup Session via the application server's registry
	nextHop, err := s.applicationServer.GetSession(nextID)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		s.logger.DErrorWith("Next hop session not found",
			slog.F("session_id", s.sessionID),
			slog.F("next_id", nextID),
			slog.F("err", err))
		return
	}

	s.logger.DebugWith("Forwarding Request",
		slog.F("req_type", payload.ReqType),
		slog.F("next_hop", nextID),
		slog.F("remaining_path", target[1:]),
	)

	// Determine if Next Hop is Promiscuous (Intermediate) or Leaf
	if nextHop.GetSSHClient() != nil && len(target) > 1 {
		// GATEWAY / INTERMEDIATE
		// Forward as slider-forward-request
		remainingPath := target[1:]

		newPayload := types.ForwardRequestPayload{
			Target:  remainingPath,
			ReqType: payload.ReqType,
			Payload: payload.Payload,
		}
		newData, mErr := json.Marshal(newPayload)
		if mErr != nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			s.logger.DErrorWith("Failed to marshal new payload",
				slog.F("session_id", s.sessionID),
				slog.F("err", mErr))
			return
		}

		ok, reply, sErr := nextHop.GetSSHClient().SendRequest("slider-forward-request", req.WantReply, newData)
		if sErr != nil {
			s.logger.DErrorWith("Failed to send forward request",
				slog.F("session_id", s.sessionID),
				slog.F("err", sErr))
			return
		}
		if req.WantReply {
			_ = req.Reply(ok, reply)
		}
		return
	}

	// End of path - Send request to target client via ServerConn
	if nextHop.GetSSHServerConn() == nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		s.logger.DErrorWith("Next hop session has no SSH connection",
			slog.F("session_id", s.sessionID),
			slog.F("next_id", nextID))
		return
	}

	ok, reply, sErr := nextHop.GetSSHServerConn().SendRequest(payload.ReqType, req.WantReply, payload.Payload)
	if sErr != nil {
		s.logger.DErrorWith("Failed to send request to target",
			slog.F("session_id", s.sessionID),
			slog.F("err", sErr))
		return
	}
	if req.WantReply {
		_ = req.Reply(ok, reply)
	}
}

// eventRequest defines the payload for slider-event request
type eventRequest struct {
	Type      string `json:"type"`       // e.g., "disconnect"
	SessionID int64  `json:"session_id"` // Local ID that caused the event
	Timestamp int64  `json:"timestamp"`
}

// handleSliderEvent handles slider-event requests (gateway servers only)
func (s *BidirectionalSession) handleSliderEvent(req *ssh.Request) {
	var event eventRequest
	if err := json.Unmarshal(req.Payload, &event); err != nil {
		s.logger.DErrorWith("Failed to unmarshal event",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	s.logger.InfoWith("Received Upstream Event",
		slog.F("type", event.Type),
		slog.F("remote_session_id", event.SessionID),
	)

	if req.WantReply {
		_ = req.Reply(true, nil)
	}
}

// handleShutdown handles shutdown requests (all roles)
func (s *BidirectionalSession) handleShutdown(req *ssh.Request) {
	s.logger.InfoWith("Received shutdown request, closing connection",
		slog.F("session_id", s.sessionID))

	// Reply to acknowledge the shutdown
	if req.WantReply {
		_ = req.Reply(true, nil)
	}

	// Close connections based on role
	if s.role.IsAgent() {
		// For outbound agent connections, close SSH client
		if s.sshClient != nil {
			_ = s.sshClient.Close()
		}
	}

	// Close WebSocket connection to trigger cleanup
	if s.wsConn != nil {
		_ = s.wsConn.Close()
	}
}
