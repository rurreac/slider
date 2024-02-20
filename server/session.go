package server

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slider/pkg/sconn"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.org/x/crypto/ssh"

	"golang.org/x/term"

	"github.com/gorilla/websocket"
)

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

func (s *server) addSessionChannel(session *Session, channel ssh.Channel) {
	var mutex sync.Mutex
	mutex.Lock()
	session.shellChannel = channel
	mutex.Unlock()
}

func (s *server) closeSessionChannel(session *Session) {
	var mutex sync.Mutex
	mutex.Lock()
	_ = session.shellChannel.Close()
	mutex.Unlock()
}

func (s *server) sessionExecute(session *Session) {
	// Remote Command won't execute on PTY, so terminal must be restored
	// and make RAW once the output is finished
	_ = term.Restore(int(os.Stdin.Fd()), s.consoleState)
	defer func() {
		// Force terminal back to RAW for Slider Console
		_, _ = term.MakeRaw(int(os.Stdin.Fd()))

		// Close SSH Session
		s.closeSessionChannel(session)
	}()

	// Copy ssh channel to stdout. Copy will stop on exit.
	if _, outCopyErr := io.Copy(os.Stdout, session.shellChannel); outCopyErr != nil {
		s.Debugf("Copy stdout: %s", outCopyErr)
	}
}

func (s *server) sessionInteractive(session *Session) {
	// Ensure Session Channel is closed
	defer s.closeSessionChannel(session)

	// Consider Reverse Shell is opened
	session.shellOpened = true
	defer func() {
		// Force terminal back to RAW for Slider Console
		_, _ = term.MakeRaw(int(os.Stdin.Fd()))
	}()

	var msgOut string
	if !session.rawTerm {
		// - Console terminal is RAW as this Remote Shell is not PTY,
		// 		terminal state must be reverted to its original state, NOT RAW
		_ = term.Restore(int(os.Stdin.Fd()), s.consoleState)

		// - This Terminal in Reverse Shell has ECHO, it could be fixed (if not Windows not ConPTY)
		// 		creating your own Terminal with ECHO disabled.
		fmt.Printf(
			"\r\n%sCurrent Terminal is NOT RAW.\n\r"+
				"An extra intro is required to recover control of Slider Console after exit.%s\n\n\r",
			string(s.console.Escape.Yellow),
			string(s.console.Escape.Reset))

		// - Once Reverse Shell is closed and extra intro is required to recover the control of the terminal.
		msgOut = fmt.Sprintf("\r%sPress INTRO to return to Console.\n\r%s",
			string(s.console.Escape.Yellow),
			string(s.console.Escape.Reset))
	} else {
		// - This Reverse-Shell is PTY and can be RAW, since Slider Console is RAW there is nothing to set.

		// - This session shell has PTY which allow us to update the PTY size at the Client Origin
		//		according to window-change events on the Server Terminal, sending Connection Requests.
		winChange := make(chan os.Signal, 1)
		signal.Notify(winChange, syscall.SIGWINCH)

		go s.captureWindowChange(session, winChange)

		fmt.Printf(
			"\r\n%sEntering fully interactive Shell...%s\n\n\r",
			string(s.console.Escape.Yellow),
			string(s.console.Escape.Reset))

		msgOut = fmt.Sprintf("\r%sPress any key to return to Console.\n\r%s",
			string(s.console.Escape.Yellow),
			string(s.console.Escape.Reset))
	}

	go func() {
		// Copy ssh channel to stdout. Copy will stop on exit.
		if _, outCopyErr := io.Copy(os.Stdout, session.shellChannel); outCopyErr != nil {
			s.Debugf("Copy stdout: %s", outCopyErr)
		}

		// Remote Shell is closed, print out message
		fmt.Printf("%s", msgOut)
	}()

	// TODO: Copy should terminate if Shell is closed otherwise user interaction is required to force an EOF error.
	// Copy all stdin to ssh channel.

	_, _ = io.Copy(session.shellChannel, os.Stdin)

	// TODO: Manage this along with Sessions

	// Reverse Shell is closed
	session.shellOpened = false

	s.Debugf("Closed Session ID %d Reverse Shell (%s).", session.sessionID, session.shellWsConn.RemoteAddr().String())
}

// captureWindowChange captures windows size changes and send them to the Client PTY
func (s *server) captureWindowChange(session *Session, winChange chan os.Signal) {
	// TODO: Events could be packed in 3-5s since the first event sending the just the latest.
	for range winChange {
		if session.shellOpened {
			if cols, rows, sizeErr := term.GetSize(int(os.Stdin.Fd())); sizeErr == nil {
				s.Debugf("Session ID %d - Terminal size changed: rows %d cols %d.\n", session.sessionID, rows, cols)
				newTermSize := &sconn.TermSize{
					Rows: rows,
					Cols: cols,
				}
				if newTermSizeBytes, mErr := json.Marshal(newTermSize); mErr == nil {
					// Send window-change event without expecting confirmation or answer
					_, _, _ = s.sendConnRequest(session, "window-change", false, newTermSizeBytes)
				}
			} else {
				break
			}
		} else {
			break
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
