package client

import (
	"fmt"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"strings"
	"sync"
	"sync/atomic"
)

type Session struct {
	Logger        *slog.Logger
	logID         string
	sessionID     int64
	serverAddr    string
	wsConn        *websocket.Conn
	sshConn       ssh.Conn
	sessionMutex  sync.Mutex
	KeepAliveChan chan bool
	keepAliveOn   bool
	disconnect    chan bool
	interpreter   *interpreter.Interpreter
	initTermSize  *conf.TermDimensions
}

func (c *client) newWebSocketSession(wsConn *websocket.Conn) *Session {
	c.sessionTrackMutex.Lock()
	defer c.sessionTrackMutex.Unlock()
	sc := atomic.AddInt64(&c.sessionTrack.SessionCount, 1)
	sa := atomic.AddInt64(&c.sessionTrack.SessionActive, 1)
	c.sessionTrack.SessionCount = sc
	c.sessionTrack.SessionActive = sa

	host := strings.Split(wsConn.RemoteAddr().String(), ":")[0]
	if host == "" {
		host = "localhost"
	}

	session := &Session{
		sessionID:     sc,
		serverAddr:    host,
		wsConn:        wsConn,
		KeepAliveChan: make(chan bool, 1),
		disconnect:    make(chan bool, 1),
		Logger:        c.Logger,
	}

	if c.isListener {
		session.logID = fmt.Sprintf(
			"Session ID %d (%s) - ",
			sc,
			wsConn.RemoteAddr().String(),
		)
	}
	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		c.Logger.Fatalf("Interpreter not supported - %v", iErr)
	}
	session.interpreter = i
	c.sessionTrack.Sessions[sc] = session

	c.Logger.Debugf("Sessions -> Global: %d, Active: %d (Session ID %d: %s)",
		sc, sa, sa, session.wsConn.RemoteAddr().String())
	return session
}

func (c *client) dropWebSocketSession(session *Session) {
	c.sessionTrackMutex.Lock()

	if session.keepAliveOn {
		session.KeepAliveChan <- true
		close(session.KeepAliveChan)
		session.keepAliveOn = false
	}

	sa := atomic.AddInt64(&c.sessionTrack.SessionActive, -1)
	c.sessionTrack.SessionActive = sa

	_ = session.wsConn.Close()

	c.Logger.Debugf("Sessions <- Global: %d, Active: %d (Dropped Session ID %d: %s)",
		c.sessionTrack.SessionCount,
		sa,
		session.sessionID,
		session.wsConn.RemoteAddr().String(),
	)

	delete(c.sessionTrack.Sessions, session.sessionID)
	c.sessionTrackMutex.Unlock()
}

func (s *Session) setInitTermSize(initSize conf.TermDimensions) {
	s.sessionMutex.Lock()
	s.initTermSize = &conf.TermDimensions{
		Width:  initSize.Width,
		Height: initSize.Height,
		X:      initSize.X,
		Y:      initSize.Y,
	}
	s.sessionMutex.Unlock()
}

func (s *Session) handleSSHRequests(requests <-chan *ssh.Request, winChange chan<- []byte, envChange chan<- []byte) {
	for req := range requests {
		ok := false
		if req.Type != "env" {
			s.Logger.Debugf("SSH Request \"%s\" - Request Type \"%s\" - payload: %v", "shell", req.Type, req.Payload)
		}

		switch req.Type {
		case "env":
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			envChange <- req.Payload
		case "window-change":
			if s.interpreter.PtyOn {
				ok = true
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			winChange <- req.Payload
		default:
			s.Logger.Warnf("SSH Rejected request type %s", req.Type)
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		}
	}
}
