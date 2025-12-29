package server

import (
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"
	"slider/server/remote"
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
	sshClient           *ssh.Client
	sshChannel          ssh.Channel
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
	Router              *remote.Router
	initTermSize        types.TermDimensions
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

	s.InfoWith("Session Stats (↑)",
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

	s.InfoWith("Session Stats (↓)",
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

func (session *Session) setSSHClient(client *ssh.Client) {
	session.sessionMutex.Lock()
	session.sshClient = client
	if client != nil {
		session.SocksInstance.SetSSHConn(client)
		session.ShellInstance.SetSSHConn(client)
		session.SSHInstance.SetSSHConn(client)
	}
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
	if session.clientInterpreter == nil {
		return false
	}
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
			session.Logger.DebugWith("KeepAlive Check Stopped",
				slog.F("session_id", session.sessionID),
			)
			return
		case <-ticker.C:
			ok, p, sendErr := session.sendRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil {
				session.Logger.ErrorWith("KeepAlive Connection Error Received",
					slog.F("session_id", session.sessionID),
					slog.F("err", sendErr),
				)
				return
			}
			if !ok || string(p) != "pong" {
				// Just warn, don't kill connection.
				// The fact that we got a reply (even false) means the connection is alive.
				session.Logger.WarnWith("KeepAlive Reply mismatch (non-fatal)",
					slog.F("session_id", session.sessionID),
					slog.F("ok", ok),
					slog.F("payload", string(p)),
				)
			}
		}
	}
}

func (session *Session) sendRequest(requestType string, wantReply bool, payload []byte) (bool, []byte, error) {
	var err error
	var pOk bool
	var resPayload []byte

	// pOk, resPayload, err = session.sshConn.SendRequest(requestType, wantReply, payload)
	if session.sshClient != nil {
		pOk, resPayload, err = session.sshClient.SendRequest(requestType, wantReply, payload)
	} else if session.sshConn != nil {
		pOk, resPayload, err = session.sshConn.SendRequest(requestType, wantReply, payload)
	} else {
		return false, nil, fmt.Errorf("no active connection")
	}
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
	session.Logger.DebugWith("Replying Connection Request",
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
	ptyOn := false
	if session.clientInterpreter != nil {
		ptyOn = session.clientInterpreter.PtyOn
	}
	session.ShellInstance.SetPtyOn(ptyOn)
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
	ptyOn := false
	if session.clientInterpreter != nil {
		ptyOn = session.clientInterpreter.PtyOn
	}
	session.SSHInstance.SetPtyOn(ptyOn)
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

	// For promiscuous sessions, use sshClient; otherwise use sshConn
	if session.sshClient != nil {
		config.SetSSHConn(session.sshClient)
	} else if session.sshConn != nil {
		config.SetSSHConn(session.sshConn)
	}

	ptyOn := false
	if session.clientInterpreter != nil {
		ptyOn = session.clientInterpreter.PtyOn
	}
	config.SetPtyOn(ptyOn)
	config.SetEnvVarList(envVarList)

	return config
}

func (session *Session) newSftpClient() (*sftp.Client, error) {
	session.Logger.Debugf("Opening SFTP channel to client")

	var sftpChan ssh.Channel
	var requests <-chan *ssh.Request
	var err error

	if session.sshClient != nil {
		sftpChan, requests, err = session.sshClient.OpenChannel("sftp", nil)
	} else if session.sshConn != nil {
		sftpChan, requests, err = session.sshConn.OpenChannel("sftp", nil)
	} else {
		return nil, fmt.Errorf("no active connection")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open SFTP channel: %v", err)
	}

	go ssh.DiscardRequests(requests)

	cleanup := func() {
		session.Logger.DebugWith("Closing SFTP channel due to error",
			slog.F("session_id", session.sessionID),
		)
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
		session.Logger.DebugWith("SFTP client connection closed",
			slog.F("session_id", session.sessionID),
		)
	}()

	session.Logger.DebugWith("SFTP client connected successfully",
		slog.F("session_id", session.sessionID),
	)
	return client, nil
}

// GetSSHClient returns the SSH client connection (for promiscuous mode)
func (session *Session) GetSSHClient() *ssh.Client {
	session.sessionMutex.Lock()
	defer session.sessionMutex.Unlock()
	return session.sshClient
}

// GetLogger returns the session logger
func (session *Session) GetLogger() *slog.Logger {
	return session.Logger
}

// GetID returns the session ID
func (session *Session) GetID() int64 {
	return session.sessionID
}

// GetSSHConn returns the SSH server connection
func (session *Session) GetSSHConn() ssh.Conn {
	session.sessionMutex.Lock()
	defer session.sessionMutex.Unlock()
	return session.sshConn
}

// AddSessionChannel satisfies the remote.Session interface
func (session *Session) AddSessionChannel(ch ssh.Channel) {
	session.addSessionChannel(ch)
}

// HandleForwardedTcpIpChannel satisfies the remote.Session interface
func (session *Session) HandleForwardedTcpIpChannel(nc ssh.NewChannel) {
	session.handleForwardedTcpIpChannel(nc)
}

func (session *Session) SetInitTermSize(size types.TermDimensions) {
	session.sessionMutex.Lock()
	session.initTermSize = size
	session.sessionMutex.Unlock()
}

func (session *Session) GetInitTermSize() types.TermDimensions {
	session.sessionMutex.Lock()
	defer session.sessionMutex.Unlock()
	return session.initTermSize
}
