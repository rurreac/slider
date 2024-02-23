package server

import (
	"bytes"
	"encoding/json"
	"fmt"
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

	"golang.org/x/term"

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

func (session *Session) sessionInteractive(initTermState *term.State, console *term.Terminal) {
	// Consider Reverse Shell is opened
	session.shellOpened = true

	defer func() {
		// Ensure Session Channel is closed
		session.closeSessionChannel()
		// Force terminal back to RAW for Slider Console
		_, _ = term.MakeRaw(int(os.Stdin.Fd()))
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
		winChange := make(chan os.Signal, 1)
		signal.Notify(winChange, syscall.SIGWINCH)

		go session.captureWindowChange(winChange)

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
					if _, _, err := session.sendRequestAndRetry(
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
	/*
		A NOTE REGARDING BELOW:
		- Connection failures from Server don't actually mean Client is offline (current status)
		- Attempts restored always after attempt #1
		- KeepAlive from Client doesn't fail
		- Should add retries as a flag?
		-
	*/
	allowConnFailures := 3
	connFailures := 0

	for {
		select {
		case <-session.KeepAliveChan:
			session.Debugf("Keep-Alive SessionID %d - KeepAlive Check Stopped.", session.sessionID)
			return
		case <-ticker.C:
			ok, p, sendErr := session.sendRequestAndRetry("keep-alive", true, []byte("ping"))
			if sendErr != nil {
				session.Errorf(
					"Keep-Alive SessionID %d - KeepAlive Ping Failure - Connection Error \"%s\"",
					session.sessionID,
					sendErr,
				)
				return
			}
			if !bytes.Equal(p, []byte("pong")) || !ok {
				if connFailures >= allowConnFailures {
					session.Errorf(
						"Keep-Alive SessionID %d - Ping Failure - Giving up after \"%d\" Attempts.",
						session.sessionID,
						allowConnFailures,
					)
					return
				} else {
					connFailures++
					session.Warnf(
						"Keep-Alive SessionID %d - Ping Failure - Attempt #%d (ok:\"%v\", data:\"%s\")",
						session.sessionID,
						connFailures,
						ok,
						p,
					)
				}
				continue
			}
			if connFailures > 0 {
				session.Warnf(
					"Keep-Alive SessionID %d - Reset Failure Counter on Attempt #%d",
					session.sessionID,
					connFailures,
				)
				connFailures = 0
			}
		}
	}
}

// readInput is just a test to try and minimize the user interaction due to io.Copy holding for a byte read until EOF
func (s *server) readInput(session *Session) {
	var readInput = make([]byte, 512)
	for {
		n, err := os.Stdin.Read(readInput[0:])
		if err == io.EOF {
			fmt.Printf("\r\nClient disconnected\n")
			break
		} else if err != nil {
			fmt.Printf("\r\n%v\n", err)
			break
		}
		if _, err = session.shellChannel.Write(readInput[0:n]); err != nil {
			_, _ = os.Stdout.Write(readInput[0:n])
			if _, err = s.console.Write(readInput[0:n]); err != nil {
				fmt.Printf("\r\nError writing to Console")
			}
			break
		}
	}
}

func (session *Session) sendRequestAndRetry(requestType string, wantReply bool, payload []byte) (bool, []byte, error) {
	var err error
	retry := time.Now().Add(time.Second * 5)
	counter := 1
	var pOk bool
	var resPayload []byte
	for {
		pOk, resPayload, err = session.shellConn.SendRequest(requestType, wantReply, payload)
		if err != nil {
			return false, nil, fmt.Errorf("connection request failed \"'%v' - '%s' - '%s'\"", pOk, resPayload, err)
		}
		if pOk {
			var pMsg string
			if len(payload) != 0 {
				pMsg = fmt.Sprintf("with Payload: \"%s\" ", payload)
			}
			session.Debugf(
				"Sent Connection Request Type \"%s\" to SessionID %d %s(Attempt #%d)",
				requestType,
				session.sessionID,
				pMsg,
				counter,
			)
			break
		}
		if !pOk && retry.After(time.Now()) {
			counter++
			time.Sleep(time.Second * 1)
		} else if retry.Before(time.Now()) {
			return false, nil, fmt.Errorf(
				"connection request to SessionID %d failed after %d attempts",
				session.sessionID,
				counter,
			)
		}
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
