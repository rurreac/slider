package server

import (
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/sftp"

	"golang.org/x/crypto/ssh"

	"github.com/gorilla/websocket"
)

type certInfo struct {
	fingerprint string
	id          int64
}

// Session represents an active client connection to the server.
// It manages the WebSocket and SSH connections, along with various
// endpoint instances (SOCKS, SSH, Shell) and SFTP state.
type Session struct {
	Logger              *slog.Logger
	notifier            chan error
	hostIP              string
	sessionID           int64
	wsConn              *websocket.Conn
	sshConn             *ssh.ServerConn
	sshChannel          ssh.Channel
	rawTerm             bool
	KeepAliveChan       chan bool
	keepAliveOn         bool
	SocksInstance       *instance.Config
	clientInterpreter   *interpreter.Interpreter
	isListener          bool
	sessionMutex        sync.Mutex
	certInfo            certInfo
	sshConf             *ssh.ServerConfig
	SSHInstance         *instance.Config
	ShellInstance       *instance.Config
	SftpHistory         *CustomHistory
	sftpCommandRegistry *CommandRegistry
	sftpContext         *SftpCommandContext
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

	shellInstance := instance.New(
		&instance.Config{
			Logger:               s.Logger,
			SessionID:            sc,
			EndpointType:         instance.ShellEndpoint,
			CertificateAuthority: s.CertificateAuthority,
		},
	)

	socksInstance := instance.New(
		&instance.Config{
			Logger:       s.Logger,
			SessionID:    sc,
			EndpointType: instance.SocksEndpoint,
		},
	)

	sshInstance := instance.New(
		&instance.Config{
			Logger:       s.Logger,
			SessionID:    sc,
			EndpointType: instance.SshEndpoint,
			ServerKey:    s.serverKey,
			AuthOn:       s.authOn,
		},
	)

	session := &Session{
		sessionID:     sc,
		hostIP:        host,
		wsConn:        wsConn,
		KeepAliveChan: make(chan bool, 1),
		Logger:        s.Logger,
		sshConf:       s.sshConf,
		SocksInstance: socksInstance,
		SSHInstance:   sshInstance,
		ShellInstance: shellInstance,
		SftpHistory: &CustomHistory{
			entries: make([]string, 0),
			maxSize: conf.DefaultHistorySize,
		},
	}

	s.sessionTrack.Sessions[sc] = session
	s.sessionTrackMutex.Unlock()

	s.WithCaller().InfoWith("Session Stats (↑)", nil,
		slog.F("global", sc),
		slog.F("active", sa),
		slog.F("session_id", sc),
		slog.F("remote_addr", session.wsConn.RemoteAddr().String()),
	)

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

	s.WithCaller().InfoWith("Session Stats (↓)", nil,
		slog.F("global", s.sessionTrack.SessionCount),
		slog.F("active", sa),
		slog.F("session_id", session.sessionID),
		slog.F("remote_addr", session.wsConn.RemoteAddr().String()),
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
	session.SocksInstance.SetSSHConn(sshConn)
	session.ShellInstance.SetSSHConn(sshConn)
	session.SSHInstance.SetSSHConn(sshConn)
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

func (session *Session) addSessionNotifier(notifier chan error) {
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
			session.Logger.WithCaller().DebugWith("KeepAlive Check Stopped",
				nil,
				slog.F("session_id", session.sessionID),
			)
			return
		case <-ticker.C:
			ok, p, sendErr := session.sendRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !ok || string(p) != "pong" {
				session.Logger.WithCaller().ErrorWith("KeepAlive Connection Error Received",
					nil,
					slog.F("session_id", session.sessionID),
					slog.F("ok", ok),
					slog.F("payload", p),
					slog.F("err", sendErr),
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
		pMsg = fmt.Sprintf("%v", payload)
	}
	session.Logger.WithCaller().DebugWith("Replying Connection Request",
		nil,
		slog.F("session_id", session.sessionID),
		slog.F("request_type", request.Type),
		slog.F("ok", ok),
		slog.F("payload", pMsg),
	)
	return request.Reply(ok, payload)
}

func (session *Session) socksEnable(port int, exposePort bool, notifier chan error) {
	session.SocksInstance.SetExpose(exposePort)

	if sErr := session.SocksInstance.StartEndpoint(port); sErr != nil {
		notifier <- sErr
	}

}

func (session *Session) shellEnable(port int, exposePort bool, tlsOn bool, interactiveOn bool, notifier chan error) {
	session.ShellInstance.SetPtyOn(session.clientInterpreter.PtyOn)
	session.ShellInstance.SetExpose(exposePort)

	if tlsOn {
		session.ShellInstance.SetTLSOn(tlsOn)
		if interactiveOn {
			session.ShellInstance.SetInteractiveOn(interactiveOn)
			defer session.ShellInstance.SetInteractiveOn(false)
		}
		if sErr := session.ShellInstance.StartTLSEndpoint(port); sErr != nil {
			notifier <- sErr
		}
	} else {
		if sErr := session.ShellInstance.StartEndpoint(port); sErr != nil {
			notifier <- sErr
		}
	}

}

func (session *Session) sshEnable(port int, exposePort bool, notifier chan error) {
	if session.SSHInstance.AuthOn {
		session.SSHInstance.SetAllowedFingerprint(session.certInfo.fingerprint)
	}
	session.SSHInstance.SetPtyOn(session.clientInterpreter.PtyOn)
	session.SSHInstance.SetExpose(exposePort)

	if sErr := session.SSHInstance.StartEndpoint(port); sErr != nil {
		notifier <- sErr
	}
}

func (session *Session) newExecInstance(envVarList []struct{ Key, Value string }) *instance.Config {
	config := instance.New(&instance.Config{
		Logger:       session.Logger,
		SessionID:    session.sessionID,
		EndpointType: instance.ExecEndpoint,
	})
	config.SetSSHConn(session.sshConn)
	config.SetPtyOn(session.clientInterpreter.PtyOn)
	config.SetEnvVarList(envVarList)

	return config
}

func (session *Session) newSftpClient() (*sftp.Client, error) {
	session.Logger.WithCaller().Debugf("Opening SFTP channel to client")

	sftpChan, requests, err := session.sshConn.OpenChannel("sftp", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open SFTP channel: %v", err)
	}

	go ssh.DiscardRequests(requests)

	cleanup := func() {
		session.Logger.WithCaller().DebugWith("Closing SFTP channel due to error",
			nil,
			slog.F("session_id", session.sessionID),
		)
		_ = sftpChan.Close()
	}

	session.Logger.WithCaller().Debugf("Initializing SFTP client")
	client, err := sftp.NewClientPipe(sftpChan, sftpChan)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create SFTP client: %v", err)
	}

	go func() {
		_ = client.Wait()
		session.Logger.WithCaller().DebugWith("SFTP client connection closed",
			nil,
			slog.F("session_id", session.sessionID),
		)
	}()

	session.Logger.WithCaller().DebugWith("SFTP client connected successfully",
		nil,
		slog.F("session_id", session.sessionID),
	)
	return client, nil
}
