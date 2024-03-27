package client

import (
	"fmt"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"os"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/ssocks"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Session struct {
	*slog.Logger
	logID         string
	sessionID     int64
	serverAddr    string
	ptyFile       *os.File
	wsConn        *websocket.Conn
	sshConn       ssh.Conn
	keepalive     time.Duration
	sessionMutex  sync.Mutex
	KeepAliveChan chan bool
	keepAliveOn   bool
	disconnect    chan bool
	interpreter   *interpreter.Interpreter
	socksInstance *ssocks.Instance
}

func (c *client) newWebSocketSession(wsConn *websocket.Conn) *Session {
	c.sessionTrackMutex.Lock()
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

	c.sessionTrack.Sessions[sc] = session
	c.sessionTrackMutex.Unlock()

	c.Debugf("Sessions -> Global: %d, Active: %d (Session ID %d: %s)",
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

	c.Debugf("Sessions <- Global: %d, Active: %d (Dropped Session ID %d: %s)",
		c.sessionTrack.SessionCount,
		sa,
		session.sessionID,
		session.wsConn.RemoteAddr().String(),
	)

	delete(c.sessionTrack.Sessions, session.sessionID)
	c.sessionTrackMutex.Unlock()
}

func (s *Session) addInterpreter(i *interpreter.Interpreter) {
	s.interpreter = i
}
