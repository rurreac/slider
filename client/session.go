package client

import (
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type Session struct {
	Logger        *slog.Logger
	sessionID     int64
	serverAddr    string
	wsConn        *websocket.Conn
	sshConn       ssh.Conn
	sessionMutex  sync.Mutex
	KeepAliveChan chan bool
	keepAliveOn   bool
	disconnect    chan bool
	interpreter   *interpreter.Interpreter
	initTermSize  *types.TermDimensions
	revPortFwdMap map[uint32]*RevPortControl
}

type RevPortControl struct {
	BindAddress string
	StopChan    chan bool
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
		revPortFwdMap: make(map[uint32]*RevPortControl),
		keepAliveOn:   false,
	}

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		c.Logger.FatalWith("Interpreter not supported",
			slog.F("err", iErr))
	}
	session.interpreter = i
	session.initTermSize = &types.TermDimensions{
		Width:  uint32(0),
		Height: uint32(0),
	}
	c.sessionTrack.Sessions[sc] = session

	c.Logger.DebugWith("Session Stats (↑)",
		slog.F("global", sc),
		slog.F("active", sa),
		slog.F("session_id", session.sessionID),
		slog.F("remote_addr", session.wsConn.RemoteAddr().String()))
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

	c.Logger.DebugWith("Session Stats (↓)",
		slog.F("global", c.sessionTrack.SessionCount),
		slog.F("active", sa),
		slog.F("session_id", session.sessionID),
		slog.F("remote_addr", session.wsConn.RemoteAddr().String()))

	delete(c.sessionTrack.Sessions, session.sessionID)
	c.sessionTrackMutex.Unlock()
}

func (s *Session) setInitTermSize(initSize types.TermDimensions) {
	s.sessionMutex.Lock()
	s.initTermSize = &types.TermDimensions{
		Width:  initSize.Width,
		Height: initSize.Height,
		X:      initSize.X,
		Y:      initSize.Y,
	}
	s.sessionMutex.Unlock()
}

func (s *Session) addTcpIpForward(tcpIpReq *types.CustomTcpIpFwdRequest, stopChan chan bool) {
	s.sessionMutex.Lock()
	s.revPortFwdMap[tcpIpReq.BindPort] = &RevPortControl{
		BindAddress: tcpIpReq.BindAddress,
		StopChan:    stopChan,
	}
	s.sessionMutex.Unlock()
}

func (s *Session) dropTcpIpForward(port uint32) {
	s.sessionMutex.Lock()
	delete(s.revPortFwdMap, port)
	s.sessionMutex.Unlock()
}

func (s *Session) handleSSHRequests(requests <-chan *ssh.Request, winChange chan<- []byte, envChange chan<- []byte) {
	for req := range requests {
		ok := false
		if req.Type != "env" {
			s.Logger.DebugWith("SSH Request",
				slog.F("session_id", s.sessionID),
				slog.F("request_type", req.Type),
				slog.F("payload", req.Payload))
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
			s.Logger.WarnWith("SSH Rejected request type",
				slog.F("session_id", s.sessionID),
				slog.F("request_type", req.Type))
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		}
	}
}
