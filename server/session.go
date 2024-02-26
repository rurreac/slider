package server

import (
	"encoding/json"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"os/signal"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gorilla/websocket"
)

// Session represents a session from a client to the server
type Session struct {
	host          string
	sessionID     int64
	shellWsConn   *websocket.Conn
	shellConn     *ssh.ServerConn
	shellChannel  ssh.Channel
	shellOpened   bool
	rawTerm       bool
	KeepAliveChan chan bool
	*slog.Logger
}

// newWebSocketSession adds a new session and stores the client info
func (s *server) newWebSocketSession(wsConn *websocket.Conn) *Session {
	var mutex sync.Mutex

	mutex.Lock()
	sc := atomic.AddInt64(&s.sessionTrack.SessionCount, 1)
	sa := atomic.AddInt64(&s.sessionTrack.SessionActive, 1)
	s.sessionTrack.SessionCount = sc
	s.sessionTrack.SessionActive = sa

	host := strings.Split(wsConn.RemoteAddr().String(), ":")[0]
	if host == "" {
		host = "localhost"
	}

	session := &Session{
		sessionID:     sc,
		host:          host,
		shellWsConn:   wsConn,
		KeepAliveChan: make(chan bool, 1),
		Logger:        s.Logger,
	}
	s.sessionTrack.Sessions[sc] = session
	mutex.Unlock()

	s.Infof("Sessions -> Global: %d, Active: %d (Session ID %d: %s)",
		sc, sa, sa, session.shellWsConn.RemoteAddr().String())
	return session
}

// dropWebSocketSession removes a session and its client info
func (s *server) dropWebSocketSession(session *Session) {
	var mutex sync.Mutex

	mutex.Lock()
	session.KeepAliveChan <- true
	close(session.KeepAliveChan)

	sa := atomic.AddInt64(&s.sessionTrack.SessionActive, -1)
	s.sessionTrack.SessionActive = sa

	_ = session.shellConn.Close()
	_ = session.shellWsConn.Close()

	s.Infof("Sessions -> Global: %d, Active: %d (Dropped Session ID %d: %s)",
		s.sessionTrack.SessionCount,
		sa,
		session.sessionID,
		session.shellWsConn.RemoteAddr().String(),
	)

	delete(s.sessionTrack.Sessions, session.sessionID)
	mutex.Unlock()
}

func (s *server) getSession(sessionID int) (*Session, error) {
	session := s.sessionTrack.Sessions[int64(sessionID)]
	if session == nil {
		return nil, fmt.Errorf("session ID %d not found", sessionID)
	}
	return session, nil
}

func (session *Session) addSessionChannel(channel ssh.Channel) {
	var mutex sync.Mutex
	mutex.Lock()
	session.shellChannel = channel
	mutex.Unlock()
}

func (session *Session) closeSessionChannel() {
	var mutex sync.Mutex
	mutex.Lock()
	_ = session.shellChannel.Close()
	mutex.Unlock()
}

func (session *Session) sessionExecute(initTermState *term.State) error {
	// Remote Command won't execute on PTY, so terminal must be restored
	// and make RAW once the output is finished
	_ = term.Restore(int(os.Stdin.Fd()), initTermState)
	defer func() {
		// Force terminal back to RAW for Slider Console
		_, _ = term.MakeRaw(int(os.Stdin.Fd()))

		// Close SSH Session
		session.closeSessionChannel()
	}()

	// Copy ssh channel to stdout. Copy will stop on exit.
	if _, outCopyErr := io.Copy(os.Stdout, session.shellChannel); outCopyErr != nil {
		return fmt.Errorf("copy stdout: %s", outCopyErr)
	}
	return nil
}

func (session *Session) sessionInteractive(initTermState *term.State, console *term.Terminal, winChangeCall syscall.Signal) {
	// Consider Reverse Shell is opened
	session.shellOpened = true

	defer func() {
		// Force terminal back to RAW for Slider Console
		_, _ = term.MakeRaw(int(os.Stdin.Fd()))
		// Ensure Session Channel is closed
		session.closeSessionChannel()
		// Reverse Shell is closed
		session.shellOpened = false
	}()
	var msgOut string
	if !session.rawTerm {
		// - Console terminal is RAW as this Remote Shell is not PTY,
		// 		terminal state must be reverted to its original state, NOT RAW
		_ = term.Restore(int(os.Stdin.Fd()), initTermState)

		// - This Terminal in Reverse Shell has ECHO, it could be fixed (if not Windows not ConPTY)
		// 		creating your own Terminal with ECHO disabled.
		fmt.Printf(
			"\r%sCurrent Terminal is NOT RAW.\n\r"+
				"An extra intro is required to recover control of Slider Console after exit.%s\n\n\r",
			string(console.Escape.Yellow),
			string(console.Escape.Reset))

		// - Once Reverse Shell is closed and extra intro is required to recover the control of the terminal.
		msgOut = fmt.Sprintf("\r%sPress INTRO to return to Console.\n\r%s",
			string(console.Escape.Yellow),
			string(console.Escape.Reset))
	} else {
		// - This Reverse-Shell is PTY and can be RAW, since Slider Console is RAW there is nothing to set.
		// - This session shell has PTY which allow us to update the PTY size at the Client Origin
		//		according to window-change events on the Server Terminal, sending Connection Requests.
		if winChangeCall != 0 {
			winChange := make(chan os.Signal, 1)
			defer close(winChange)
			signal.Notify(winChange, winChangeCall)

			go session.captureWindowChange(winChange)
		}

		fmt.Printf(
			"\r%sEntering fully interactive Shell...%s\n\r",
			string(console.Escape.Yellow),
			string(console.Escape.Reset))

		msgOut = fmt.Sprintf("\r%sPress any key to return to Console.\n\r%s",
			string(console.Escape.Yellow),
			string(console.Escape.Reset))
	}

	go func() {
		// Copy ssh channel to stdout. Copy will stop on exit.
		_, _ = io.Copy(os.Stdout, session.shellChannel)

		// Remote Shell is closed, print out message
		fmt.Printf("%s", msgOut)
	}()

	// TODO: Copy should terminate if Shell is closed otherwise user interaction is required to force an EOF error.
	// Copy all stdin to ssh channel.
	_, _ = io.Copy(session.shellChannel, os.Stdin)

	session.Debugf(
		"Session ID %d - Closed Reverse Shell (%s).",
		session.sessionID,
		session.shellWsConn.RemoteAddr().String(),
	)
}

// captureWindowChange captures windows size changes and send them to the Client PTY
func (session *Session) captureWindowChange(winChange chan os.Signal) {
	// TODO: Events could be packed in 3-5s since the first event sending the just the latest.
	for range winChange {
		if session.shellOpened {
			if cols, rows, sizeErr := term.GetSize(int(os.Stdin.Fd())); sizeErr == nil {
				session.Debugf(
					"Terminal size changed: rows %d cols %d.\n",
					rows,
					cols,
				)
				newTermSize := &interpreter.TermSize{
					Rows: rows,
					Cols: cols,
				}
				if newTermSizeBytes, mErr := json.Marshal(newTermSize); mErr == nil {
					// Send window-change event without expecting confirmation or answer
					if _, _, err := session.sendRequest(
						"window-change",
						false,
						newTermSizeBytes,
					); err != nil {
						session.Errorf("%s", err)
					}
				}
			} else {
				break
			}
		} else {
			break
		}
	}
}

func (session *Session) keepAlive(keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-session.KeepAliveChan:
			session.Debugf("Keep-Alive SessionID %d - KeepAlive Check Stopped.", session.sessionID)
			return
		case <-ticker.C:
			ok, p, sendErr := session.sendRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !ok || string(p) != "pong" {
				session.Errorf(
					"Keep-Alive SessionID %d - Connection Error Received (\"%v\"-\"%s\"-\"%s\")",
					session.sessionID,
					ok,
					p,
					sendErr,
				)
				return
			}
		}
	}
}

func (session *Session) sendRequest(requestType string, wantReply bool, payload []byte) (bool, []byte, error) {
	var err error
	var pOk bool
	var resPayload []byte

	pOk, resPayload, err = session.shellConn.SendRequest(requestType, wantReply, payload)
	if err != nil || !pOk {
		return false, nil, fmt.Errorf("connection request failed \"'%v' - '%s' - '%s'\"", pOk, resPayload, err)
	}

	return pOk, resPayload, err
}

func (session *Session) replyConnRequest(request *ssh.Request, ok bool, payload []byte) error {
	var pMsg string
	if len(payload) != 0 {
		pMsg = fmt.Sprintf("with Payload: \"%s\" ", payload)
	}
	session.Debugf(
		"Replying Connection Request Type \"%s\" from SessionID %d, will send \"%v\" %s",
		request.Type,
		session.sessionID,
		ok,
		pMsg,
	)
	return request.Reply(ok, payload)
}
