package server

import (
	"encoding/json"
	"fmt"
	"os"
	"slider/pkg/conf"
	"slider/pkg/sconn"
	"slider/pkg/slog"
	"slider/pkg/types"
	"slider/server/remote"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (s *server) NewSSHServer(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	s.DebugWith(
		"Established WebSocket connection with client",
		slog.F("session_id", session.sessionID),
		slog.F("remote_addr", netConn.RemoteAddr().String()),
	)

	var sshServerConn *ssh.ServerConn
	var newChan <-chan ssh.NewChannel
	var reqChan <-chan *ssh.Request
	var err error

	sshConf := session.sshConf
	// Use a new SSH Configuration with authentication disabled
	// when the Server connects to a Listener Client
	if session.isListener {
		sshConf.NoClientAuth = true
	}

	sshServerConn, newChan, reqChan, err = ssh.NewServerConn(netConn, sshConf)
	if err != nil {
		s.DErrorWith("Failed to create SSH server", slog.F("err", err))
		if session.notifier != nil {
			session.notifier <- err
		}
		return
	}
	session.addSessionSSHConnection(sshServerConn)

	// If authentication was enabled and not connecting to a listener save the client certificate info
	if s.authOn && !session.isListener {
		if certID, cErr := strconv.Atoi(sshServerConn.Permissions.Extensions["cert_id"]); cErr == nil {
			session.addCertInfo(
				int64(certID),
				sshServerConn.Permissions.Extensions["fingerprint"],
			)
		}

	}

	s.DebugWith(
		"Upgraded Websocket transport to SSH Connection",
		slog.F("session_id", session.sessionID),
		slog.F("host", session.sshConn.RemoteAddr().String()),
		slog.F("client_version", session.sshConn.ClientVersion()),
	)

	if session.notifier != nil {
		session.notifier <- nil
	}

	// Handle Keep Alive
	go session.keepAlive(s.keepalive)

	// Create and configure router
	router := remote.NewRouter(s.Logger)
	router.RegisterHandler("session", remote.HandleSession)
	router.RegisterHandler("forwarded-tcpip", remote.HandleForwardedTcpIp)
	router.RegisterHandler("slider-connect", remote.HandleSliderConnect)
	router.RegisterHandler("sftp", remote.HandleSftp)
	router.RegisterHandler("init-size", remote.HandleInitSize)
	router.RegisterHandler("shell", remote.HandleShell)
	session.Router = router

	// Handle incoming requests
	go func() {
		for nc := range newChan {
			go func(nnc ssh.NewChannel) {
				if err := router.Route(nnc, session, s); err != nil {
					s.DErrorWith("Channel routing error", slog.F("err", err))
				}
			}(nc)
		}
	}()
	go s.handleConnRequests(session, reqChan)

	// Block until connection closes
	_ = sshServerConn.Wait()
}

// HandleForwardRequest processes generic forwarded requests
func (s *server) HandleForwardRequest(req *ssh.Request, session *Session) error {
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
	nextHopSession, err := s.getSession(nextID)
	if err != nil {
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return fmt.Errorf("next hop session %d not found: %w", nextID, err)
	}

	session.Logger.DebugWith("Forwarding Request",
		slog.F("req_type", payload.ReqType),
		slog.F("next_hop", nextID),
		slog.F("remaining_path", target[1:]),
	)

	// Determine if Next Hop is Promiscuous (Intermediate) or Leaf
	if nextHopSession.sshClient != nil && len(target) > 1 {
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

		ok, reply, sErr := nextHopSession.sshClient.SendRequest("slider-forward-request", req.WantReply, newData)
		if sErr != nil {
			return sErr
		}
		if req.WantReply {
			_ = req.Reply(ok, reply)
		}
		return nil

	} else {
		// LEAF (or end of path)
		// Unwrap and send original request
		// Note: We use sshConn (Server connection) NOT sshClient.
		// Wait, if it's a Client Session (Standard), we communicate via `ssh.ServerConn`?
		// `nextHopSession` is a session on THIS server.
		// If it is a Standard Client, `sshConn` is the connection *from* the client.
		// We want to send a request *to* the client.

		// If nextHopSession.sshConn is nil?
		if nextHopSession.sshConn == nil {
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return fmt.Errorf("next hop session %d has no SSH connection", nextID)
		}

		ok, reply, sErr := nextHopSession.sshConn.SendRequest(payload.ReqType, req.WantReply, payload.Payload)
		if sErr != nil {
			return sErr
		}
		if req.WantReply {
			_ = req.Reply(ok, reply)
		}
		return nil
	}
}

func (s *server) handleConnRequests(session *Session, connReq <-chan *ssh.Request) {
	for r := range connReq {
		var payload []byte
		switch r.Type {
		case "window-size":
			// Could be checking size from os.Stdin Fd
			//  but os.Stdout Fd is the one that works with Windows as well
			width, height, err := term.GetSize(int(os.Stdout.Fd()))
			if err != nil {
				session.Logger.Errorf("Failed to obtain terminal size")
			}
			tSize := types.TermDimensions{
				Height: uint32(height),
				Width:  uint32(width),
			}
			payload, _ = json.Marshal(tSize)
			_ = session.replyConnRequest(r, true, payload)
		case "keep-alive":
			session.Logger.DebugWith("Received keep-alive request", slog.F("session_id", session.sessionID))
			replyErr := session.replyConnRequest(r, true, []byte("pong"))
			if replyErr != nil {
				session.Logger.DErrorWith("Connection error while replying.",
					slog.F("session_id", session.sessionID),
					slog.F("request_type", r.Type),
					slog.F("err", replyErr),
				)
				return
			}
		case "client-info":
			ci := &conf.ClientInfo{}
			if jErr := json.Unmarshal(r.Payload, ci); jErr != nil {
				session.Logger.DErrorWith("Failed to parse Client Info",
					slog.F("session_id", session.sessionID),
					slog.F("err", jErr),
				)
			}
			session.setInterpreter(ci.Interpreter)

			// Reply with our own (Server) interpreter so the client knows who we are
			serverInterp := *s.serverInterpreter
			// Note: If we don't support PTY, we might want to suggest a fallback shell
			// based on the client's reported capabilities, but for now just identification
			// is most important.

			interpreterPayload, jErr := json.Marshal(serverInterp)
			if jErr != nil {
				session.Logger.DErrorWith("Error marshaling Server Info",
					slog.F("session_id", session.sessionID),
					slog.F("err", jErr),
				)
				_ = session.replyConnRequest(r, true, nil)
			} else {
				_ = session.replyConnRequest(r, true, interpreterPayload)
			}
		case "slider-sessions":
			if err := s.HandleSessionsRequest(r, session); err != nil {
				session.Logger.DErrorWith("Failed to handle slider-sessions request",
					slog.F("session_id", session.sessionID),
					slog.F("err", err),
				)
			}
		case "slider-forward-request":
			if err := s.HandleForwardRequest(r, session); err != nil {
				session.Logger.DErrorWith("Failed to handle forward request",
					slog.F("session_id", session.sessionID),
					slog.F("err", err),
				)
			}
		case "slider-event":
			if err := s.HandleEventRequest(r, session); err != nil {
				session.Logger.DErrorWith("Failed to handle slider-event request",
					slog.F("session_id", session.sessionID),
					slog.F("err", err),
				)
			}
		default:
			session.Logger.DebugWith("Rejected unknown request type",
				slog.F("request_type", r.Type))
			if r.WantReply {
				_ = r.Reply(false, nil)
			}
		}

	}
}

func (session *Session) handleForwardedTcpIpChannel(nc ssh.NewChannel) {
	var err error
	var requests <-chan *ssh.Request
	session.Logger.DebugWith("Forwarded TCP IP Channel",
		slog.F("session_id", session.sessionID),
	)

	forwardedChannel, requests, err := nc.Accept()
	if err != nil {
		session.Logger.DErrorWith("Failed to accept channel",
			slog.F("session_id", session.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("err", err),
		)
		return
	}
	defer func() { _ = forwardedChannel.Close() }()
	go ssh.DiscardRequests(requests)

	payload := &types.CustomTcpIpChannelMsg{}

	if uErr := json.Unmarshal(nc.ExtraData(), payload); uErr != nil {
		session.Logger.DErrorWith("Failed to parse ssh channel extra data",
			slog.F("session_id", session.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("extra_data", nc.ExtraData()),
			slog.F("err", uErr),
		)
		return
	}

	// Set the forwarded channel in the port forwarding manager
	if session.SSHInstance.GetPortForwardManager() != nil {
		session.SSHInstance.GetPortForwardManager().SetForwardedChannel(forwardedChannel)
	}

	// Find PortFwd mapping
	boundPort := int(payload.DstPort)
	control, mErr := session.SSHInstance.GetRemotePortMapping(boundPort)
	if mErr != nil {
		// This should never happen
		session.Logger.ErrorWith("Failed to find PortFwd mapping",
			slog.F("session_id", session.sessionID),
			slog.F("bound_port", boundPort),
			slog.F("err", mErr),
		)
		return
	}

	tcpIpMsg := &types.TcpIpChannelMsg{
		DstHost: payload.DstHost,
		DstPort: payload.DstPort,
		SrcHost: payload.SrcHost,
		SrcPort: payload.SrcPort,
	}
	if payload.IsSshConn {
		session.Logger.DebugWith("Received SSH TCPIP Forwarded channel",
			slog.F("session_id", session.sessionID),
			slog.F("bound_port", boundPort),
			slog.F("dst_host", control.DstHost),
			slog.F("dst_port", control.DstPort),
		)
		// Send the payload to the SSH instance
		control.RcvChan <- tcpIpMsg
		// Wait until done
		<-control.DoneChan
	} else {
		session.Logger.DebugWith("Received MSG TCPIP Forwarded channel",
			slog.F("session_id", session.sessionID),
			slog.F("bound_port", boundPort),
			slog.F("src_host", control.SrcHost),
			slog.F("src_port", control.SrcPort),
			slog.F("dst_host", control.DstHost),
			slog.F("dst_port", control.DstPort),
		)
		// Send the payload to the msg request
		control.RcvChan <- tcpIpMsg
		// Wait until done
		<-control.DoneChan
	}

}
