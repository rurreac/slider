package server

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slider/pkg/colors"
	"slider/pkg/interpreter"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/ssocks"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/term"

	"golang.org/x/crypto/ssh"

	"github.com/gorilla/websocket"
)

// Session represents a session from a client to the server
type Session struct {
	*slog.Logger
	hostIP            string
	sessionID         int64
	shellWsConn       *websocket.Conn
	shellConn         *ssh.ServerConn
	shellChannel      ssh.Channel
	shellOpened       bool
	rawTerm           bool
	KeepAliveChan     chan bool
	keepAliveOn       bool
	SocksInstance     *ssocks.Instance
	ClientInterpreter *interpreter.Interpreter
	sessionMutex      sync.Mutex
}

// newWebSocketSession adds a new session and stores the client info
func (s *server) newWebSocketSession(wsConn *websocket.Conn) *Session {
	s.sessionTrackMutex.Lock()
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
		hostIP:        host,
		shellWsConn:   wsConn,
		KeepAliveChan: make(chan bool, 1),
		Logger:        s.Logger,
		SocksInstance: &ssocks.Instance{
			InstanceConfig: &ssocks.InstanceConfig{},
		},
	}
	s.sessionTrack.Sessions[sc] = session
	s.sessionTrackMutex.Unlock()

	s.Infof("Sessions -> Global: %d, Active: %d (Session ID %d: %s)",
		sc, sa, sa, session.shellWsConn.RemoteAddr().String())
	return session
}

// dropWebSocketSession removes a session and its client info
func (s *server) dropWebSocketSession(session *Session) {
	s.sessionTrackMutex.Lock()

	if session.keepAliveOn {
		session.KeepAliveChan <- true
		close(session.KeepAliveChan)
		session.keepAliveOn = false
	}

	if session.SocksInstance.IsEnabled() {
		_ = session.SocksInstance.Stop()
	}

	sa := atomic.AddInt64(&s.sessionTrack.SessionActive, -1)
	s.sessionTrack.SessionActive = sa

	_ = session.shellWsConn.Close()

	s.Infof("Sessions -> Global: %d, Active: %d (Dropped Session ID %d: %s)",
		s.sessionTrack.SessionCount,
		sa,
		session.sessionID,
		session.shellWsConn.RemoteAddr().String(),
	)

	delete(s.sessionTrack.Sessions, session.sessionID)
	s.sessionTrackMutex.Unlock()
}

func (s *server) getSession(sessionID int) (*Session, error) {
	session := s.sessionTrack.Sessions[int64(sessionID)]
	if session == nil {
		return nil, fmt.Errorf("session ID %d not found", sessionID)
	}
	return session, nil
}

func (session *Session) addSessionSSHConnection(sshConn *ssh.ServerConn) {
	session.sessionMutex.Lock()
	session.shellConn = sshConn
	session.sessionMutex.Unlock()
}

func (session *Session) addSessionChannel(channel ssh.Channel) {
	session.sessionMutex.Lock()
	session.shellChannel = channel
	session.sessionMutex.Unlock()
}

func (session *Session) setKeepAliveOn(aliveCheck bool) {
	session.sessionMutex.Lock()
	session.keepAliveOn = aliveCheck
	session.sessionMutex.Unlock()
}

func (session *Session) closeSessionChannel() {
	session.sessionMutex.Lock()
	_ = session.shellChannel.Close()
	session.sessionMutex.Unlock()
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
		return fmt.Errorf("copy stdout: %v", outCopyErr)
	}
	return nil
}

func (session *Session) sessionInteractive(initTermState *term.State, winChangeCall syscall.Signal) {
	// Consider Reverse Shell is opened
	session.shellOpened = true

	defer func() {
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
			"\r%sCurrent Terminal is NOT RAW.\r\n"+
				"An extra intro is required to recover control of Slider Console after exit.%s\r\n\n",
			string(colors.Console.Warn),
			string(colors.Reset))

		// - Once Reverse Shell is closed and extra intro is required to recover the control of the terminal.
		msgOut = fmt.Sprintf("\r%s%sPress INTRO to return to Console.\r\n%s",
			string(colors.Reset),
			string(colors.Console.Warn),
			string(colors.Reset))
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
			"\r%sEntering fully interactive Shell...%s\r\n",
			string(colors.Console.Warn),
			string(colors.Reset))

		msgOut = fmt.Sprintf("\r%s%sPress any key to return to Console.\r\n%s",
			string(colors.Reset),
			string(colors.Console.Warn),
			string(colors.Reset))
	}

	go func() {
		// Copy ssh channel to stdout. Copy will stop on exit.
		_, _ = io.Copy(os.Stdout, session.shellChannel)

		// Remote Shell is closed, print out message
		fmt.Printf("%s", msgOut)
	}()

	// TODO: Copy should terminate if Shell is closed otherwise user interaction is required to force an EOF error.
	// This io.Copy always requires input as os.Stdin is a blocker
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
						session.Errorf("%v", err)
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
	session.setKeepAliveOn(true)
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
					"Keep-Alive SessionID %d - Connection Error Received (\"%v\"-\"%s\"-\"%v\")",
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
		return false, nil, fmt.Errorf("connection request failed \"'%v' - '%s' - '%v'\"", pOk, resPayload, err)
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

func (session *Session) socksEnable(port int) {
	sConfig := &ssocks.InstanceConfig{
		Logger:     session.Logger,
		IsEndpoint: true,
		Port:       port,
		SSHConn:    session.shellConn,
	}
	session.sessionMutex.Lock()
	session.SocksInstance = ssocks.New(sConfig)
	session.sessionMutex.Unlock()

	if sErr := session.SocksInstance.StartEndpoint(); sErr != nil {
		session.Errorf("Session ID %d - SOCKS - %v", session.sessionID, sErr)
	}
}

func (session *Session) uploadFile(src, dst string) <-chan sio.Status {
	status := make(chan sio.Status)
	fileList, action := sio.NewFileAction(session.shellConn, src, dst)
	go func() {
		for s := range action.UploadToClient(fileList) {
			status <- s
		}
		close(status)
	}()

	return status
}

func (session *Session) downloadFile(src, dst string) <-chan sio.Status {
	status := make(chan sio.Status)
	fileList, action := sio.NewFileAction(session.shellConn, src, dst)
	go func() {
		for s := range action.DownloadFromClient(fileList) {
			status <- s
		}
		close(status)
	}()

	return status
}

func (session *Session) downloadFileBatch(fileListPath string) <-chan sio.Status {
	status := make(chan sio.Status)
	fileList, action, err := sio.NewBatchAction(session.shellConn, fileListPath)
	if err != nil {
		status <- sio.Status{
			FileInfo: sio.FileInfo{},
			Success:  false,
			Err:      fmt.Errorf("failed to create batch action"),
		}
		close(status)
		return status
	}
	go func() {
		for s := range action.DownloadFromClient(fileList) {
			status <- s
		}
		close(status)
	}()

	return status
}
