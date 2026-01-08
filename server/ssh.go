package server

import (
	"encoding/json"
	"fmt"
	"strconv"

	"slider/pkg/remote"
	"slider/pkg/sconn"
	pkgsession "slider/pkg/session"
	"slider/pkg/slog"
	"slider/pkg/types"

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

// RouteForwardRequest processes generic forwarded requests by routing them through the mesh
func (s *server) RouteForwardRequest(req *ssh.Request, session *pkgsession.BidirectionalSession) error {
	var payload types.ForwardRequestPayload
	if err := json.Unmarshal(req.Payload, &payload); err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return fmt.Errorf("failed to unmarshal forward payload: %w", err)
	}

	target := payload.Target

	// Parse path to find next hop
	// Path format: [id1, id2, ...]
	if len(target) == 0 {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return fmt.Errorf("empty target path in forward request")
	}

	nextID := int(target[0])

	// Lookup Session
	nextHop, err := s.GetSession(nextID)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return fmt.Errorf("next hop session %d not found: %w", nextID, err)
	}

	session.GetLogger().DebugWith("Forwarding Request",
		slog.F("req_type", payload.ReqType),
		slog.F("next_hop", nextID),
		slog.F("remaining_path", target[1:]),
	)

	// Determine if Next Hop is Promiscuous (Intermediate) or Leaf
	if nextHop.GetSSHClient() != nil && len(target) > 1 {
		// PROMISOUS / INTERMEDIATE
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
			return fmt.Errorf("failed to marshal new payload: %w", mErr)
		}

		ok, reply, sErr := nextHop.GetSSHClient().SendRequest("slider-forward-request", req.WantReply, newData)
		if sErr != nil {
			return sErr
		}
		if req.WantReply {
			_ = req.Reply(ok, reply)
		}
		return nil

	}
	// End of path
	// Send request to target client via ServerConn

	// If nextHop.GetSSHServerConn() is nil?
	if nextHop.GetSSHServerConn() == nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return fmt.Errorf("next hop session %d has no SSH connection", nextID)
	}

	ok, reply, sErr := nextHop.GetSSHServerConn().SendRequest(payload.ReqType, req.WantReply, payload.Payload)
	if sErr != nil {
		return sErr
	}
	if req.WantReply {
		_ = req.Reply(ok, reply)
	}
	return nil
}
