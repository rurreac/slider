package server

import (
	"encoding/json"
	"os"
	"slider/pkg/conf"
	"slider/pkg/sconn"
	"slider/pkg/slog"
	"slider/pkg/types"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (s *server) NewSSHServer(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	s.WithCaller().DebugWith(
		"Established WebSocket connection with client",
		nil,
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
		s.WithCaller().DErrorWith("Failed to create SSH server", nil, slog.F("err", err))
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

	s.WithCaller().DebugWith(
		"Upgraded Websocket transport to SSH Connection",
		nil,
		slog.F("session_id", session.sessionID),
		slog.F("host", session.sshConn.RemoteAddr().String()),
		slog.F("client_version", session.sshConn.ClientVersion()),
	)

	if session.notifier != nil {
		session.notifier <- nil
	}

	// Set keepalive after connection is established
	go session.keepAlive(s.keepalive)

	// Requests and NewChannel channels must be serviced/discarded or the connection hangs
	go s.handleConnRequests(session, reqChan)

	s.handleNewChannels(session, newChan)

}

func (s *server) handleNewChannels(session *Session, newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		var chanReq <-chan *ssh.Request
		var sshChan ssh.Channel
		var err error

		switch nc.ChannelType() {
		case "session":
			sshChan, chanReq, err = nc.Accept()
			if err != nil {
				session.Logger.WithCaller().DErrorWith(
					"Failed to accept the channel",
					nil,
					slog.F("session_id", session.sessionID),
					slog.F("channel_type", nc.ChannelType()),
					slog.F("err", err),
				)
				return
			}
			session.addSessionChannel(sshChan)
			session.Logger.WithCaller().DebugWith(
				"Accepted SSH Channel Connection",
				nil,
				slog.F("session_id", session.sessionID),
				slog.F("channel_type", nc.ChannelType()),
			)
		case "forwarded-tcpip":
			go session.handleForwardedTcpIpChannel(nc)
		default:
			session.Logger.WithCaller().DebugWith("Rejected channel", nil, slog.F("channel_type", nc.ChannelType()))
			if err = nc.Reject(ssh.UnknownChannelType, ""); err != nil {
				session.Logger.WithCaller().DErrorWith("Received Unknown channel type",
					nil,
					slog.F("session_id", session.sessionID),
					slog.F("channel_type", nc.ChannelType()),
					slog.F("err", err),
				)
			}
			return
		}
		go s.handleChanRequests(session, chanReq)
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
				session.Logger.WithCaller().Errorf("Failed to obtain terminal size")
			}
			tSize := types.TermDimensions{
				Height: uint32(height),
				Width:  uint32(width),
			}
			payload, _ = json.Marshal(tSize)
			_ = session.replyConnRequest(r, true, payload)
		case "keep-alive":
			replyErr := session.replyConnRequest(r, true, []byte("pong"))
			if replyErr != nil {
				session.Logger.WithCaller().DErrorWith("Connection error while replying.",
					nil,
					slog.F("session_id", session.sessionID),
					slog.F("request_type", r.Type),
					slog.F("err", replyErr),
				)
				return
			}
		case "client-info":
			ci := &conf.ClientInfo{}
			if jErr := json.Unmarshal(r.Payload, ci); jErr != nil {
				session.Logger.WithCaller().DErrorWith("Failed to parse Client Info",
					nil,
					slog.F("session_id", session.sessionID),
					slog.F("err", jErr),
				)
			}
			session.setInterpreter(ci.Interpreter)

			interpreterPayload := make([]byte, 0)
			if !s.serverInterpreter.PtyOn {
				cliInterpreter := ci.Interpreter
				cliInterpreter.Shell = cliInterpreter.AltShell

				// Best effort, is server doesn't support PTY, use simple client Shell
				var jErr error
				interpreterPayload, jErr = json.Marshal(ci.Interpreter)
				if jErr != nil {
					session.Logger.WithCaller().DErrorWith("Error marshaling Client Info",
						nil,
						slog.F("session_id", session.sessionID),
						slog.F("err", jErr),
					)
				}
			}
			_ = session.replyConnRequest(r, true, interpreterPayload)
		default:
			ssh.DiscardRequests(connReq)
		}

	}
}

func (s *server) handleChanRequests(session *Session, chanReq <-chan *ssh.Request) {
	for r := range chanReq {
		ok := false
		switch r.Type {
		case "pty-req":
			ok = true
			session.rawTerm = true
			_ = session.replyConnRequest(r, ok, nil)
			session.Logger.WithCaller().DebugWith("Client Requested Raw Terminal",
				nil,
				slog.F("session_id", session.sessionID),
			)
		case "reverse-shell":
			ok = true
			_ = session.replyConnRequest(r, ok, nil)
			session.Logger.WithCaller().DebugWith("Client will send Reverse Shell",
				nil,
				slog.F("session_id", session.sessionID),
			)
			return
		default:
			_ = session.replyConnRequest(r, ok, nil)
			session.Logger.WithCaller().DebugWith("Unknown channel request",
				nil,
				slog.F("session_id", session.sessionID),
				slog.F("request_type", r.Type),
			)
			return
		}
	}
}

func (session *Session) handleForwardedTcpIpChannel(nc ssh.NewChannel) {
	// Prevent another go routine to smash session.SSHInstance.ForwardedSshChannel
	// by locking the session until the content has been processed
	session.SSHInstance.FTx.ForwardingMutex.Lock()
	defer session.SSHInstance.FTx.ForwardingMutex.Unlock()

	var err error
	var requests <-chan *ssh.Request
	session.Logger.WithCaller().DebugWith("Forwarded TCP IP Channel",
		nil,
		slog.F("session_id", session.sessionID),
	)
	session.SSHInstance.FTx.ForwardedSshChannel, requests, err = nc.Accept()
	if err != nil {
		session.Logger.WithCaller().DErrorWith("Failed to accept channel",
			nil,
			slog.F("session_id", session.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("err", err),
		)
		return
	}
	defer func() { _ = session.SSHInstance.FTx.ForwardedSshChannel.Close() }()
	go ssh.DiscardRequests(requests)

	payload := &types.CustomTcpIpChannelMsg{}

	if uErr := json.Unmarshal(nc.ExtraData(), payload); uErr != nil {
		session.Logger.WithCaller().DErrorWith("Failed to parse ssh channel extra data",
			nil,
			slog.F("session_id", session.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("extra_data", nc.ExtraData()),
			slog.F("err", uErr),
		)
		return
	}

	// Find PortFwd mapping
	boundPort := int(payload.DstPort)
	control, mErr := session.SSHInstance.GetRemotePortMapping(boundPort)
	if mErr != nil {
		// This should never happen
		session.Logger.WithCaller().ErrorWith("Failed to find PortFwd mapping",
			nil,
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
		session.Logger.WithCaller().DebugWith("Received SSH TCPIP Forwarded channel",
			nil,
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
		session.Logger.WithCaller().DebugWith("Received MSG TCPIP Forwarded channel",
			nil,
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
