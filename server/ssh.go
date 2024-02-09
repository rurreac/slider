package server

import (
	"encoding/json"
	"fmt"
	"os"
	"slider/pkg/sconn"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

func (s *server) NewSSHServer(session *Session) {
	netConn := sconn.WsConnToNetConn(session.shellWsConn)
	sshConn, newChan, reqChan, err := ssh.NewServerConn(netConn, s.sshConf)
	if err != nil {
		s.Errorf("Failed to create SSH server %s", err)
		return
	}
	// TODO: Reverse-Shell sessions could be closed on demand
	// Sessions are closed on SessionInteractive
	session.shellConn = sshConn

	s.Debugf(
		"New SSH Server with WebSocket as underlying transport connected to client \"%s\"",
		netConn.RemoteAddr().String(),
	)

	user := sshConn.User()
	if user == "" {
		user = "<unknown>"
	}
	s.Debugf(
		"SSH Connection received from user: %s, address: %s, client version: %s, session: %v",
		user,
		sshConn.RemoteAddr().String(),
		sshConn.ClientVersion(),
		sshConn.SessionID(),
	)

	// Request channel must be serviced/discarded or the connection hangs
	var r *ssh.Request

	if r = <-reqChan; true {
		var payload []byte

		if r.Type == "window-size" {
			if width, height, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
				tSize := sconn.TermSize{
					Rows: height,
					Cols: width,
				}
				payload, _ = json.Marshal(tSize)
			}
			s.answerSSHRequestType(r, true, payload)
		} else {
			ssh.DiscardRequests(reqChan)
		}
	}

	for nc := range newChan {
		// Discard non session channels
		if ct := nc.ChannelType(); ct != "session" {
			s.Debugf("Rejected channel %s", nc.ChannelType())
			if err := nc.Reject(ssh.UnknownChannelType, ""); err != nil {
				s.Warnf("handleSSHnewChannels (session): Received Unknown channel type.\n%s", err)
			}
			return
		}
		s.HandleSSHChannels(session, nc)
	}
}

// HandleSSHChannels receives a new SSH Channel of Type session and process its request
func (s *server) HandleSSHChannels(session *Session, nc ssh.NewChannel) {
	channel, chanReq, err := nc.Accept()
	if err != nil {
		s.Errorf("handleSSHChannels (Accept): Failed to accept the request.\n%s", err)
		return
	}
	s.Debugf("Accepted SSH Session Channel.")
	// Save channel to Session
	session.shellChannel = channel

	for r := range chanReq {
		ok := false
		switch r.Type {
		case "request-pty":
			ok = true
			session.rawTerm = true
			s.answerSSHRequestType(r, ok, nil)
			s.Debugf("Session %d Client Requested Raw Terminal...", session.sessionID)
		case "reverse-shell":
			ok = true
			s.answerSSHRequestType(r, ok, nil)
			s.Debugf("Session %d Client Sent Reverse Shell...", session.sessionID)
			return
		default:
			s.answerSSHRequestType(r, ok, nil)
			return
		}
	}
}

// answerSSHRequestType answers a Request adding log verbosity
func (s *server) answerSSHRequestType(req *ssh.Request, ok bool, payload []byte) {
	// A bit verbose for better comprehension. Known request types expect a reply.
	if req.WantReply {
		var p string
		if payload != nil {
			p = fmt.Sprintf("with Payload: %s", payload)
		}
		s.Debugf("Received Request Type \"%s\" wants reply, will send \"%v\" %s", req.Type, ok, p)
		if err := req.Reply(ok, payload); err != nil {
			s.Errorf("req.Reply error: %s", err)
		}
	}
}

func (s *server) sendSSHConnRequest(session *Session, requestType string, wantReply bool, payload []byte) (bool, []byte, error) {
	s.Debugf("Session ID %d - Sending Request Type \"%s\" with Payload: %s", session.sessionID, requestType, payload)
	return session.shellConn.SendRequest(requestType, wantReply, payload)
}
