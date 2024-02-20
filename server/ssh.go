package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slider/pkg/sconn"
	"sync"
	"time"

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
		go s.keepAlive(session, s.conf.keepalive)
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
				s.Errorf(
					"Session ID %d - handleSSHChannels (Accept): Failed to accept the request.\n%s",
					session.sessionID,
					err,
				)
				return
			}
			s.addSessionChannel(session, sessChan)
			s.Debugf(
				"Session ID %d - Accepted SSH \"%s\" Channel Connection.",
				session.sessionID,
				nc.ChannelType(),
			)
		default:
			s.Debugf("Rejected channel %s", nc.ChannelType())
			if err := nc.Reject(ssh.UnknownChannelType, ""); err != nil {
				s.Warnf("handleSSHnewChannels (session): Received Unknown channel type.\n%s", err)
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
				tSize := sconn.TermSize{
					Rows: height,
					Cols: width,
				}
				payload, _ = json.Marshal(tSize)
			}
			s.replyChanRequest(r, true, payload)
		case "keep-alive":
			replyErr := s.replyConnRequest(session, r, true, []byte("pong"))
			if replyErr != nil {
				s.Errorf("[Keep-Alive] Connection error while replying.")
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
			s.replyChanRequest(r, ok, nil)
			s.Debugf("Session %d Client Requested Raw Terminal...", session.sessionID)
		case "reverse-shell":
			ok = true
			s.replyChanRequest(r, ok, nil)
			s.Debugf("Session %d Client Sent Reverse Shell...", session.sessionID)
			return
		default:
			s.replyChanRequest(r, ok, nil)
			return
		}
	}
}

// replyChanRequest answers a Request adding log verbosity
func (s *server) replyChanRequest(req *ssh.Request, ok bool, payload []byte) {
	if req.WantReply {
		var p string
		if payload != nil {
			p = fmt.Sprintf("with Payload: \"%s\"", payload)
		}
		s.Debugf("Received Channel Request Type \"%s\" wants reply, will send \"%v\" %s", req.Type, ok, p)
		if err := req.Reply(ok, payload); err != nil {
			s.Errorf("req.Reply error: %s", err)
		}
	}
}

func (s *server) sendConnRequest(session *Session, requestType string, wantReply bool, payload []byte) (bool, []byte, error) {
	var mutex sync.Mutex
	mutex.Lock()
	s.Debugf("Session ID %d - Sending Connection Request Type \"%s\" with Payload: \"%s\"", session.sessionID, requestType, payload)
	sOk, sP, sErr := session.shellConn.SendRequest(requestType, wantReply, payload)
	mutex.Unlock()
	return sOk, sP, sErr
}

func (s *server) replyConnRequest(session *Session, req *ssh.Request, ok bool, payload []byte) error {
	s.Debugf("Session ID %d - Replying Connection Request Type \"%s\" will send \"%v\" with Payload: %s", session.sessionID, req.Type, ok, payload)
	return req.Reply(ok, payload)
}

func (s *server) keepAlive(session *Session, keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()
	/*
		A NOTE REGARDING BELOW:
		- Connection failures from Server don't actually mean Client is offline (current status)
		- Attempts restored always after attempt #1
		- KeepAlive from Client doesn't fail
		- Should add retries as a flag?
	*/
	allowConnFailures := 3
	connFailures := 0

	for {
		select {
		case <-session.KeepAliveChan:
			s.Debugf("SessionID %d - KeepAlive Check Stopped.", session.sessionID)
			return
		case <-ticker.C:
			ok, p, sendErr := s.sendConnRequest(session, "keep-alive", true, []byte("ping"))
			if sendErr != nil {
				s.Errorf(
					"Session ID %d - KeepAlive Ping Failure - Connection Error \"%s\"",
					session.sessionID,
					sendErr,
				)
				return
			}
			if !bytes.Equal(p, []byte("pong")) || !ok {
				if connFailures >= allowConnFailures {
					s.Errorf(
						"Session ID %d - KeepAlive Ping Failure - Giving up after \"%d\" Attempts.",
						session.sessionID,
						allowConnFailures,
					)
					return
				} else {
					connFailures++
					s.Warnf(
						"Session ID %d - KeepAlive Ping Failure - Attempt #%d (ok:\"%v\", data:\"%s\")",
						session.sessionID,
						connFailures,
						ok,
						p,
					)
				}
				continue
			}
			if connFailures > 0 {
				s.Warnf(
					"Session ID %d - KeepAlive Connection Reset Failure Counter after Attempt #%d",
					session.sessionID,
					connFailures,
				)
				connFailures = 0
			}
		}
	}
}
