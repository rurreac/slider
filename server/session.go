package server

import (
	"fmt"
	"github.com/pkg/sftp"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gorilla/websocket"
)

type certInfo struct {
	fingerprint string
	id          int64
}

// Session represents a session from a client to the server
type Session struct {
	Logger            *slog.Logger
	LogPrefix         string
	notifier          chan bool
	hostIP            string
	sessionID         int64
	wsConn            *websocket.Conn
	sshConn           *ssh.ServerConn
	sshChannel        ssh.Channel
	rawTerm           bool
	KeepAliveChan     chan bool
	keepAliveOn       bool
	SocksInstance     *instance.Config
	clientInterpreter *interpreter.Interpreter
	isListener        bool
	sessionMutex      sync.Mutex
	certInfo          certInfo
	sshConf           *ssh.ServerConfig
	SSHInstance       *instance.Config
	ShellInstance     *instance.Config
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
		wsConn:        wsConn,
		KeepAliveChan: make(chan bool, 1),
		Logger:        s.Logger,
		LogPrefix:     fmt.Sprintf("SessionID %d - ", sc),
		sshConf:       s.sshConf,
	}

	shellInstance := instance.New(
		&instance.Config{
			Logger:               s.Logger,
			LogPrefix:            fmt.Sprintf("SessionID %d - SHELL ", sc),
			EndpointType:         instance.ShellOnly,
			CertificateAuthority: s.CertificateAuthority,
		},
	)

	socksInstance := instance.New(
		&instance.Config{
			Logger:       s.Logger,
			LogPrefix:    fmt.Sprintf("SessionID %d - SOCKS ", sc),
			EndpointType: instance.SocksOnly,
		},
	)

	sshInstance := instance.New(
		&instance.Config{
			Logger:    s.Logger,
			LogPrefix: fmt.Sprintf("SessionID %d - SSH ", sc),
			ServerKey: s.serverKey,
			AuthOn:    s.authOn,
		},
	)

	session.SocksInstance = socksInstance
	session.ShellInstance = shellInstance
	session.SSHInstance = sshInstance

	s.sessionTrack.Sessions[sc] = session
	s.sessionTrackMutex.Unlock()

	s.Logger.Infof("Sessions -> Global: %d, Active: %d (Session ID %d: %s)",
		sc, sa, sa, session.wsConn.RemoteAddr().String())

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

	if session.SSHInstance.IsEnabled() {
		_ = session.SSHInstance.Stop()
	}

	if session.ShellInstance.IsEnabled() {
		_ = session.ShellInstance.Stop()
	}

	sa := atomic.AddInt64(&s.sessionTrack.SessionActive, -1)
	s.sessionTrack.SessionActive = sa

	_ = session.wsConn.Close()

	s.Logger.Infof("Sessions <- Global: %d, Active: %d (Dropped Session ID %d: %s)",
		s.sessionTrack.SessionCount,
		sa,
		session.sessionID,
		session.wsConn.RemoteAddr().String(),
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
	session.sshConn = sshConn
	session.sessionMutex.Unlock()
}

func (session *Session) addSessionChannel(channel ssh.Channel) {
	session.sessionMutex.Lock()
	session.sshChannel = channel
	session.sessionMutex.Unlock()
}

func (session *Session) addCertInfo(certID int64, fingerprint string) {
	session.sessionMutex.Lock()
	session.certInfo.id = certID
	session.certInfo.fingerprint = fingerprint
	session.sessionMutex.Unlock()
}

func (session *Session) setKeepAliveOn(aliveCheck bool) {
	session.sessionMutex.Lock()
	session.keepAliveOn = aliveCheck
	session.sessionMutex.Unlock()
}

func (session *Session) setListenerOn(listener bool) {
	session.sessionMutex.Lock()
	session.isListener = listener
	session.sessionMutex.Unlock()
}

func (session *Session) setSSHConf(sshConf *ssh.ServerConfig) {
	session.sessionMutex.Lock()
	session.sshConf = sshConf
	session.sessionMutex.Unlock()
}

func (session *Session) setInterpreter(interpreter *interpreter.Interpreter) {
	session.sessionMutex.Lock()
	session.clientInterpreter = interpreter
	session.sessionMutex.Unlock()
}

func (session *Session) IsPtyOn() bool {
	session.sessionMutex.Lock()
	defer session.sessionMutex.Unlock()
	return session.clientInterpreter.PtyOn
}

func (session *Session) addSessionNotifier(notifier chan bool) {
	session.sessionMutex.Lock()
	session.notifier = notifier
	session.sessionMutex.Unlock()
}

func (session *Session) keepAlive(keepalive time.Duration) {
	session.setKeepAliveOn(true)
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-session.KeepAliveChan:
			session.Logger.Debugf(session.LogPrefix + "KeepAlive Check Stopped")
			return
		case <-ticker.C:
			ok, p, sendErr := session.sendRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !ok || string(p) != "pong" {
				session.Logger.Errorf(
					session.LogPrefix+"KeepAlive Connection Error Received (\"%v\"-\"%s\"-\"%v\")",
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

	pOk, resPayload, err = session.sshConn.SendRequest(requestType, wantReply, payload)
	if err != nil {
		return false, nil, fmt.Errorf("connection request failed \"'%v' - '%s' - '%v'\"", pOk, resPayload, err)
	}

	return pOk, resPayload, err
}

func (session *Session) replyConnRequest(request *ssh.Request, ok bool, payload []byte) error {
	var pMsg string
	if len(payload) != 0 {
		pMsg = fmt.Sprintf("with Payload: \"%s\" ", payload)
	}
	session.Logger.Debugf(
		session.LogPrefix+"Replying Connection Request Type \"%s\", will send \"%v\" %s",
		request.Type,
		ok,
		pMsg,
	)
	return request.Reply(ok, payload)
}

func (session *Session) socksEnable(port int, exposePort bool) {
	session.SocksInstance.SetExpose(exposePort)

	if sErr := session.SocksInstance.StartEndpoint(port); sErr != nil {
		session.Logger.Errorf(session.LogPrefix+"Socks - %v", sErr)
	}
}

func (session *Session) shellEnable(port int, exposePort bool, tlsOn bool, interactiveOn bool) {
	session.ShellInstance.SetPtyOn(session.clientInterpreter.PtyOn)
	session.ShellInstance.SetExpose(exposePort)

	if tlsOn {
		session.ShellInstance.SetTLSOn(tlsOn)
		if interactiveOn {
			session.ShellInstance.SetInteractiveOn(interactiveOn)
			defer session.ShellInstance.SetInteractiveOn(false)
		}
		if sErr := session.ShellInstance.StartTLSEndpoint(port); sErr != nil {
			session.Logger.Errorf(session.LogPrefix+"SHELL(TLS) - %v", sErr)
		}
	} else {
		if sErr := session.ShellInstance.StartEndpoint(port); sErr != nil {
			session.Logger.Errorf(session.LogPrefix+"SHELL - %v", sErr)
		}
	}

}

func (session *Session) sshEnable(port int, exposePort bool) {
	if session.SSHInstance.AuthOn {
		session.SSHInstance.SetAllowedFingerprint(session.certInfo.fingerprint)
	}
	session.SSHInstance.SetPtyOn(session.clientInterpreter.PtyOn)
	session.SSHInstance.SetExpose(exposePort)

	if sErr := session.SSHInstance.StartEndpoint(port); sErr != nil {
		session.Logger.Errorf(session.LogPrefix+"SSH - %v", sErr)
		return
	}
}

func (session *Session) newExecInstance(envVarList []struct{ Key, Value string }) *instance.Config {
	config := instance.New(&instance.Config{
		Logger:    session.Logger,
		LogPrefix: fmt.Sprintf("SessionID %d - EXEC ", session.sessionID),
	})
	config.SetSSHConn(session.sshConn)
	config.SetPtyOn(session.clientInterpreter.PtyOn)
	config.SetEnvVarList(envVarList)

	return config
}

func (session *Session) newSftpClient() (*sftp.Client, error) {
	session.Logger.Debugf("Opening SFTP channel to client")

	sftpChan, requests, err := session.sshConn.OpenChannel("sftp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open SFTP channel: %v", err)
	}

	go ssh.DiscardRequests(requests)

	cleanup := func() {
		session.Logger.Debugf("Closing SFTP channel due to error")
		_ = sftpChan.Close()
	}

	session.Logger.Debugf("Initializing SFTP client")
	client, err := sftp.NewClientPipe(sftpChan, sftpChan)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create SFTP client: %v", err)
	}

	go func() {
		_ = client.Wait()
		session.Logger.Debugf("SFTP client connection closed")
	}()

	session.Logger.Infof("SFTP client connected successfully")
	return client, nil
}
