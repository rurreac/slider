package server

import (
	"encoding/json"
	"os"
	"slider/pkg/conf"
	"slider/pkg/sconn"
	"strconv"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (s *server) NewSSHServer(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	s.Logger.Debugf(
		"Established WebSocket connection with client \"%s\"",
		netConn.RemoteAddr().String(),
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
		s.Logger.Errorf("Failed to create SSH server %v", err)
		if session.notifier != nil {
			session.notifier <- false
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

	s.Logger.Debugf(
		"Upgraded Websocket transport to SSH Connection: address: %s, client version: %s, session: %v",
		session.sshConn.RemoteAddr().String(),
		session.sshConn.ClientVersion(),
		session.sshConn.SessionID(),
	)

	if session.notifier != nil {
		session.notifier <- true
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
				session.Logger.Errorf(
					"Session ID %d - handleSSHChannels (Accept): Failed to accept the channel \"%s\".\n%v",
					session.sessionID,
					nc.ChannelType(),
					err,
				)
				return
			}
			session.addSessionChannel(sshChan)
			session.Logger.Debugf(
				"Session ID %d - Accepted SSH \"%s\" Channel Connection.",
				session.sessionID,
				nc.ChannelType(),
			)
		default:
			session.Logger.Debugf("Rejected channel %s", nc.ChannelType())
			if err = nc.Reject(ssh.UnknownChannelType, ""); err != nil {
				session.Logger.Warnf("Session ID %d - handleSSHnewChannels (session): Received Unknown channel type.\n%s",
					session.sessionID,
					err,
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
				session.Logger.Errorf("Failed to obtain terminal size")
			}
			tSize := conf.TermDimensions{
				Height: uint32(height),
				Width:  uint32(width),
			}
			payload, _ = json.Marshal(tSize)
			_ = session.replyConnRequest(r, true, payload)
		case "keep-alive":
			replyErr := session.replyConnRequest(r, true, []byte("pong"))
			if replyErr != nil {
				session.Logger.Errorf("Session ID %d (KeepAlive)- Connection error while replying.", session.sessionID)
				return
			}
		case "client-info":
			ci := &conf.ClientInfo{}
			if jErr := json.Unmarshal(r.Payload, ci); jErr != nil {
				s.Logger.Errorf("Failed to parse Client Info - %v", jErr)
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
					s.Logger.Errorf("Session ID %d - Error marshaling Client Info", session.sessionID)
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
			session.Logger.Debugf("Session ID %d - Client Requested Raw Terminal...", session.sessionID)
		case "reverse-shell":
			ok = true
			_ = session.replyConnRequest(r, ok, nil)
			session.Logger.Debugf("Session ID %d - Client will send Reverse Shell...", session.sessionID)
			return
		default:
			_ = session.replyConnRequest(r, ok, nil)
			return
		}
	}
}
