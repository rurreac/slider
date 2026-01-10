package session

import (
	"fmt"
	"time"

	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ========================================
// Server Mode Methods
// ========================================

// Methods specific to OperatorRole, GatewayRole, and AgentRole (when acting as target)

// EnableSocks starts the SOCKS endpoint instance
func (s *BidirectionalSession) EnableSocks(port int, expose bool, notifier chan error) error {
	if s.role.IsAgent() {
		return fmt.Errorf("SOCKS instance not available for targets")
	}

	if s.socksInstance == nil {
		return fmt.Errorf("SOCKS instance not initialized")
	}

	s.socksInstance.SetExpose(expose)

	if err := s.socksInstance.StartEndpoint(port); err != nil {
		if notifier != nil {
			notifier <- err
		}
		return err
	}

	s.logger.InfoWith("SOCKS endpoint enabled",
		slog.F("session_id", s.sessionID),
		slog.F("port", port),
		slog.F("expose", expose))
	return nil
}

// EnableSSH starts the SSH endpoint instance
func (s *BidirectionalSession) EnableSSH(port int, expose bool, notifier chan error) error {
	if s.role.IsAgent() {
		return fmt.Errorf("SSH instance not available for targets")
	}

	if s.sshInstance == nil {
		return fmt.Errorf("SSH instance not initialized")
	}

	// Set allowed fingerprint for auth
	if s.sshInstance.AuthOn {
		s.sshInstance.SetAllowedFingerprint(s.certInfo.fingerprint)
	}

	// Set PTY based on peer interpreter
	ptyOn := false
	if s.peerInterpreter != nil {
		ptyOn = s.peerInterpreter.PtyOn
	}
	s.sshInstance.SetPtyOn(ptyOn)
	s.sshInstance.SetExpose(expose)

	if err := s.sshInstance.StartEndpoint(port); err != nil {
		if notifier != nil {
			notifier <- err
		}
		return err
	}

	s.logger.InfoWith("SSH endpoint enabled",
		slog.F("session_id", s.sessionID),
		slog.F("port", port),
		slog.F("expose", expose))
	return nil
}

// EnableShell starts the Shell endpoint instance
func (s *BidirectionalSession) EnableShell(port int, expose bool, tlsOn bool, interactiveOn bool, notifier chan error) error {
	if s.role.IsAgent() {
		return fmt.Errorf("shell instance not available for targets")
	}

	if s.shellInstance == nil {
		return fmt.Errorf("shell instance not initialized")
	}

	// Set PTY based on peer interpreter
	ptyOn := false
	if s.peerInterpreter != nil {
		ptyOn = s.peerInterpreter.PtyOn
	}
	s.shellInstance.SetPtyOn(ptyOn)
	s.shellInstance.SetExpose(expose)
	s.shellInstance.SetInitTermSize(s.initTermSize)

	if tlsOn {
		s.shellInstance.SetTLSOn(tlsOn)
		if interactiveOn {
			s.shellInstance.SetInteractiveOn(interactiveOn)
			defer s.shellInstance.SetInteractiveOn(false)
		}
		if err := s.shellInstance.StartTLSEndpoint(port); err != nil {
			if notifier != nil {
				notifier <- err
			}
			return err
		}
	} else {
		if err := s.shellInstance.StartEndpoint(port); err != nil {
			if notifier != nil {
				notifier <- err
			}
			return err
		}
	}

	s.logger.InfoWith("Shell endpoint enabled",
		slog.F("session_id", s.sessionID),
		slog.F("port", port),
		slog.F("expose", expose),
		slog.F("tls", tlsOn))
	return nil
}

// GetSSHServerConn returns the SSH server connection (Operator/Gateway/Agent as listener)
func (s *BidirectionalSession) GetSSHServerConn() *ssh.ServerConn {
	return s.sshServerConn
}

// SetCertInfo sets certificate information for the session
func (s *BidirectionalSession) SetCertInfo(id int64, fingerprint string) {
	s.sessionMutex.Lock()
	s.certInfo.id = id
	s.certInfo.fingerprint = fingerprint
	s.sessionMutex.Unlock()

	s.logger.DebugWith("Certificate info set",
		slog.F("session_id", s.sessionID),
		slog.F("cert_id", id),
		slog.F("fingerprint", fingerprint))
}

// SetKeepAliveOn sets the keep-alive status
func (s *BidirectionalSession) SetKeepAliveOn(aliveCheck bool) {
	s.sessionMutex.Lock()
	s.keepAliveOn = aliveCheck
	s.sessionMutex.Unlock()
}

// SetSSHConfig sets the SSH server configuration
func (s *BidirectionalSession) SetSSHConfig(sshConfig *ssh.ServerConfig) {
	s.sessionMutex.Lock()
	s.sshConfig = sshConfig
	s.sessionMutex.Unlock()
}

// SetInterpreter sets the peer interpreter for the session
func (s *BidirectionalSession) SetInterpreter(interp *interpreter.Interpreter) {
	s.sessionMutex.Lock()
	s.peerInterpreter = interp
	s.sessionMutex.Unlock()

	// Safety check for logger (should always be set, but be defensive)
	if s.logger != nil {
		s.logger.DebugWith("Interpreter set",
			slog.F("session_id", s.sessionID),
			slog.F("shell", interp.Shell),
			slog.F("system", interp.System))
	}
}

// SetSSHServerConn sets the SSH server connection for the session
func (s *BidirectionalSession) SetSSHServerConn(conn *ssh.ServerConn) {
	s.sessionMutex.Lock()
	s.sshServerConn = conn
	s.sessionMutex.Unlock()
}

// SetWebSocketConn sets the WebSocket connection for the session
func (s *BidirectionalSession) SetWebSocketConn(conn *websocket.Conn) {
	s.sessionMutex.Lock()
	s.wsConn = conn
	s.sessionMutex.Unlock()
}

// SetSessionID sets the session ID (used during session initialization)
func (s *BidirectionalSession) SetSessionID(id int64) {
	s.sessionMutex.Lock()
	s.sessionID = id
	s.sessionMutex.Unlock()
}

// AddNotifier adds a notifier channel for the session
func (s *BidirectionalSession) AddNotifier(notifier chan error) {
	s.sessionMutex.Lock()
	s.notifier = notifier
	s.sessionMutex.Unlock()
}

// GetNotifier returns the notifier channel for the session
func (s *BidirectionalSession) GetNotifier() chan error {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.notifier
}

// GetSSHConfig returns the SSH server config for the session
func (s *BidirectionalSession) GetSSHConfig() *ssh.ServerConfig {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.sshConfig
}

// KeepAlive runs the keep-alive check loop
func (s *BidirectionalSession) KeepAlive(keepalive time.Duration) {
	s.SetKeepAliveOn(true)
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-s.KeepAliveChan:
			s.logger.DebugWith("KeepAlive check stopped",
				slog.F("session_id", s.sessionID))
			return
		case <-ticker.C:
			ok, p, sendErr := s.SendRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil {
				s.logger.ErrorWith("KeepAlive connection error",
					slog.F("session_id", s.sessionID),
					slog.F("err", sendErr))
				return
			}
			if !ok || string(p) != "pong" {
				// Just warn, don't kill connection
				s.logger.WarnWith("KeepAlive reply mismatch (non-fatal)",
					slog.F("session_id", s.sessionID),
					slog.F("ok", ok),
					slog.F("payload", string(p)))
			}
		}
	}
}

// SendRequest sends an SSH request to the connection
func (s *BidirectionalSession) SendRequest(requestType string, wantReply bool, payload []byte) (bool, []byte, error) {
	var err error
	var pOk bool
	var resPayload []byte

	if s.sshClient != nil {
		pOk, resPayload, err = s.sshClient.SendRequest(requestType, wantReply, payload)
	} else if s.sshServerConn != nil {
		pOk, resPayload, err = s.sshServerConn.SendRequest(requestType, wantReply, payload)
	} else {
		return false, nil, fmt.Errorf("no active connection")
	}

	if err != nil {
		return false, nil, fmt.Errorf("connection request failed: %v - %s - %v", pOk, resPayload, err)
	}

	return pOk, resPayload, err
}

// ReplyConnRequest replies to a connection request
func (s *BidirectionalSession) ReplyConnRequest(request *ssh.Request, ok bool, payload []byte) error {
	var pMsg string
	if len(payload) != 0 {
		pMsg = fmt.Sprintf("%v", payload)
	}
	s.logger.DebugWith("Replying connection request",
		slog.F("session_id", s.sessionID),
		slog.F("request_type", request.Type),
		slog.F("ok", ok),
		slog.F("payload", pMsg))
	return request.Reply(ok, payload)
}

// NewSftpClient creates a new SFTP client for the session
func (s *BidirectionalSession) NewSftpClient() (*sftp.Client, error) {
	s.logger.DebugWith("Opening SFTP channel to client",
		slog.F("session_id", s.sessionID))

	var sftpChan ssh.Channel
	var requests <-chan *ssh.Request
	var err error

	if s.sshClient != nil {
		sftpChan, requests, err = s.sshClient.OpenChannel("sftp", nil)
	} else if s.sshServerConn != nil {
		sftpChan, requests, err = s.sshServerConn.OpenChannel("sftp", nil)
	} else {
		return nil, fmt.Errorf("no active connection")
	}

	if err != nil {
		return nil, fmt.Errorf("failed to open SFTP channel: %v", err)
	}

	go ssh.DiscardRequests(requests)

	cleanup := func() {
		s.logger.DebugWith("Closing SFTP channel due to error",
			slog.F("session_id", s.sessionID))
		_ = sftpChan.Close()
	}

	s.logger.DebugWith("Initializing SFTP client",
		slog.F("session_id", s.sessionID))
	client, err := sftp.NewClientPipe(sftpChan, sftpChan)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create SFTP client: %v", err)
	}

	go func() {
		_ = client.Wait()
		s.logger.DebugWith("SFTP client connection closed",
			slog.F("session_id", s.sessionID))
	}()

	s.logger.DebugWith("SFTP client connected successfully",
		slog.F("session_id", s.sessionID))
	return client, nil
}

// ========================================
// SFTP State Management (OperatorRole, GatewayRole)
// ========================================

// SetSftpHistory sets the SFTP history
func (s *BidirectionalSession) SetSftpHistory(history *CustomHistory) {
	s.sftpHistory = history
}

// GetSftpHistory returns the SFTP history
func (s *BidirectionalSession) GetSftpHistory() *CustomHistory {
	return s.sftpHistory
}

// SetSftpWorkingDir sets the SFTP working directory
func (s *BidirectionalSession) SetSftpWorkingDir(dir string) {
	s.sftpWorkingDir = dir
}

// GetSftpWorkingDir returns the SFTP working directory
func (s *BidirectionalSession) GetSftpWorkingDir() string {
	return s.sftpWorkingDir
}

// ========================================
// Endpoint Instance Access (OperatorRole, GatewayRole, AgentRole)
// ========================================

// GetSocksInstance returns the SOCKS endpoint instance
func (s *BidirectionalSession) GetSocksInstance() *instance.Config {
	return s.socksInstance
}

// GetSSHInstance returns the SSH endpoint instance
func (s *BidirectionalSession) GetSSHInstance() *instance.Config {
	return s.sshInstance
}

// GetShellInstance returns the Shell endpoint instance
func (s *BidirectionalSession) GetShellInstance() *instance.Config {
	return s.shellInstance
}

// NewExecInstance creates a new execution instance for running commands
func (s *BidirectionalSession) NewExecInstance(envVarList []struct{ Key, Value string }) *instance.Config {
	execInstance := instance.New(&instance.Config{
		Logger:       s.logger,
		SessionID:    s.sessionID,
		EndpointType: instance.ExecEndpoint,
	})

	// Set SSH connection based on role
	if s.sshServerConn != nil {
		execInstance.SetSSHConn(s.sshServerConn)
	} else if s.sshClient != nil {
		execInstance.SetSSHConn(s.sshClient)
	}

	// Set environment variables if provided
	if len(envVarList) > 0 {
		execInstance.SetEnvVarList(envVarList)
	}

	return execInstance
}
