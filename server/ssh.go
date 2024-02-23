package server

import (
	"encoding/json"
	"os"
	"slider/pkg/interpreter"
	"slider/pkg/sconn"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (s *server) NewSSHServer(session *Session) {
	netConn := sconn.WsConnToNetConn(session.shellWsConn)

	var newChan <-chan ssh.NewChannel
	var reqChan <-chan *ssh.Request
	var err error

	session.shellConn, newChan, reqChan, err = ssh.NewServerConn(netConn, s.sshConf)
	if err != nil {
		s.Errorf("Failed to create SSH server %s", err)
		return
	}
	defer func() { _ = session.shellConn.Close() }()

	s.Debugf(
		"New SSH Server with WebSocket as underlying transport connected to client \"%s\"",
		netConn.RemoteAddr().String(),
	)

	user := session.shellConn.User()
	if user == "" {
		user = "<unknown>"
	}
	s.Debugf(
		"SSH Connection received from user: %s, address: %s, client version: %s, session: %v",
		user,
		session.shellConn.RemoteAddr().String(),
		session.shellConn.ClientVersion(),
		session.shellConn.SessionID(),
	)

	if s.conf.keepalive > 0 {
		go session.keepAlive(s.conf.keepalive)
	}

	// Requests and NewChannel channels must be serviced/discarded or the connection hangs
	go s.handleConnRequests(session, reqChan)

	s.handleNewChannels(session, newChan)
}

func (s *server) handleNewChannels(session *Session, newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		var chanReq <-chan *ssh.Request
		var sessChan ssh.Channel
		var err error

		switch nc.ChannelType() {
		case "session":
			sessChan, chanReq, err = nc.Accept()
			if err != nil {
				session.Errorf(
					"[Session ID %d] handleSSHChannels (Accept): Failed to accept the request.\n%s",
					session.sessionID,
					err,
				)
				return
			}
			session.addSessionChannel(sessChan)
			session.Debugf(
				"Session ID %d - Accepted SSH \"%s\" Channel Connection.",
				session.sessionID,
				nc.ChannelType(),
			)
		default:
			session.Logger.Debugf("Rejected channel %s", nc.ChannelType())
			if err = nc.Reject(ssh.UnknownChannelType, ""); err != nil {
				session.Warnf("Session ID %d - handleSSHnewChannels (session): Received Unknown channel type.\n%s",
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
			if width, height, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
				tSize := interpreter.TermSize{
					Rows: height,
					Cols: width,
				}
				payload, _ = json.Marshal(tSize)
			}
			_ = session.replyConnRequest(r, true, payload)
		case "keep-alive":
			replyErr := session.replyConnRequest(r, true, []byte("pong"))
			if replyErr != nil {
				session.Errorf("Keep-Alive Session ID %d - Connection error while replying.", session.sessionID)
				return
			}
		default:
			ssh.DiscardRequests(connReq)
		}

	}
}

func (s *server) handleChanRequests(session *Session, chanReq <-chan *ssh.Request) {
	for r := range chanReq {
		ok := false
		switch r.Type {
		case "request-pty":
			ok = true
			session.rawTerm = true
			_ = session.replyConnRequest(r, ok, nil)
			session.Debugf("Session ID %d - Client Requested Raw Terminal...", session.sessionID)
		case "reverse-shell":
			ok = true
			_ = session.replyConnRequest(r, ok, nil)
			session.Debugf("Session ID %d - Client will send Reverse Shell...", session.sessionID)
			return
		default:
			_ = session.replyConnRequest(r, ok, nil)
			return
		}
	}
}
