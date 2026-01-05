package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"slider/pkg/conf"
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
			if s.peerInterpreter != nil && s.peerInterpreter.PtyOn {
				ok = true
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			winChange <- req.Payload

		case "pty-req":
			// PTY request - typically handled before shell/exec
			ok = true
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
		if s.role == ClientRole || s.role == PromiscuousRole {
			go s.handleTcpIpForward(req)
		} else {
			s.rejectRequest(req, "tcpip-forward not supported in this role")
		}

	case "cancel-tcpip-forward":
		if s.role == ClientRole || s.role == PromiscuousRole {
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
		// Server and Listener roles handle window-size requests
		if s.role == ServerRole || s.role == ListenerRole {
			s.handleWindowSize(req)
		} else {
			s.rejectRequest(req, "window-size not supported in this role")
		}

	case "slider-sessions":
		// Only promiscuous servers (with applicationServer injected) handle this
		if s.role == ServerRole && s.applicationServer != nil {
			s.handleSliderSessions(req)
		} else {
			s.rejectRequest(req, "slider-sessions not supported in this configuration")
		}

	case "slider-forward-request":
		// Only promiscuous servers (with applicationServer injected) handle this
		if s.role == ServerRole && s.applicationServer != nil {
			s.handleSliderForwardRequest(req)
		} else {
			s.rejectRequest(req, "slider-forward-request not supported in this configuration")
		}

	case "slider-event":
		// Only promiscuous servers (with applicationServer injected) handle this
		if s.role == ServerRole && s.applicationServer != nil {
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
// This is used by ClientRole and PromiscuousRole to set up reverse port forwarding
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
			payload := &types.CustomTcpIpChannelMsg{
				IsSshConn: tcpIpForward.IsSshConn,
				TcpIpChannelMsg: &types.TcpIpChannelMsg{
					DstHost: tcpIpForward.BindAddress,
					DstPort: tcpIpForward.BindPort,
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
			channel, reqs, oErr := s.GetConnection().OpenChannel("forwarded-tcpip", customMsgBytes)
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
// This is used by ClientRole and PromiscuousRole to cancel reverse port forwarding
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
	ci := &conf.ClientInfo{}
	if jErr := json.Unmarshal(req.Payload, ci); jErr != nil {
		s.logger.DErrorWith("Failed to parse Client Info",
			slog.F("session_id", s.sessionID),
			slog.F("err", jErr))
		_ = s.ReplyConnRequest(req, true, nil)
		return
	}

	// Store interpreter info
	s.SetInterpreter(ci.Interpreter)

	// Reply with server interpreter for client identification (server roles only)
	if s.role == ServerRole || s.role == ListenerRole {
		if s.applicationServer != nil {
			// Get server interpreter from application server
			if serverInfo := s.applicationServer.GetServerInterpreter(); serverInfo != nil {
				interpreterPayload, jErr := json.Marshal(serverInfo)
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

// handleSliderSessions handles slider-sessions requests (promiscuous servers only)
func (s *BidirectionalSession) handleSliderSessions(req *ssh.Request) {
	if s.applicationServer == nil {
		s.logger.ErrorWith("Application server not set",
			slog.F("session_id", s.sessionID))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	if err := s.applicationServer.HandleSessionsRequest(req, s); err != nil {
		s.logger.DErrorWith("Failed to handle slider-sessions request",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
	}
}

// handleSliderForwardRequest handles slider-forward-request requests (promiscuous servers only)
func (s *BidirectionalSession) handleSliderForwardRequest(req *ssh.Request) {
	if s.applicationServer == nil {
		s.logger.ErrorWith("Application server not set",
			slog.F("session_id", s.sessionID))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	if err := s.applicationServer.HandleForwardRequest(req, s); err != nil {
		s.logger.DErrorWith("Failed to handle forward request",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
	}
}

// handleSliderEvent handles slider-event requests (promiscuous servers only)
func (s *BidirectionalSession) handleSliderEvent(req *ssh.Request) {
	if s.applicationServer == nil {
		s.logger.ErrorWith("Application server not set",
			slog.F("session_id", s.sessionID))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	if err := s.applicationServer.HandleEventRequest(req, s); err != nil {
		s.logger.DErrorWith("Failed to handle slider-event request",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
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
	if s.role == ClientRole || s.role == PromiscuousRole {
		// For upstream connections, close SSH client
		if s.sshClient != nil {
			_ = s.sshClient.Close()
		}
	}

	// Close WebSocket connection to trigger cleanup
	if s.wsConn != nil {
		_ = s.wsConn.Close()
	}
}
