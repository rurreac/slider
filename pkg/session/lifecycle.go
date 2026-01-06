package session

import (
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

var (
	sessionCounter int64 // Global session counter
	activeCount    int64 // Active session count
)

// NewClientToServerSession creates a new session for a client connecting to a server (ClientRole)
func NewClientToServerSession(
	logger *slog.Logger,
	wsConn *websocket.Conn,
	sshClient *ssh.Client,
	interp *interpreter.Interpreter,
	serverAddr string,
) *BidirectionalSession {
	id := atomic.AddInt64(&sessionCounter, 1)
	atomic.AddInt64(&activeCount, 1)

	logger.DebugWith("Creating client session",
		slog.F("session_id", id),
		slog.F("role", "CLIENT"),
		slog.F("server_addr", serverAddr))

	// Create local interpreter for local execution
	localInterp, _ := interpreter.NewInterpreter()

	sess := &BidirectionalSession{
		logger:           logger,
		sessionID:        id,
		role:             ClientRole,
		wsConn:           wsConn,
		sshClient:        sshClient,
		localInterpreter: localInterp,
		peerInterpreter:  interp,
		serverAddr:       serverAddr,
		channels:         make([]ssh.Channel, 0),
		revPortFwdMap:    make(map[uint32]*RevPortControl),
		KeepAliveChan:    make(chan bool, 1),
		Disconnect:       make(chan bool, 1),
		active:           true,
		// Initialize with default terminal size
		initTermSize: types.TermDimensions{
			Width:  uint32(conf.DefaultTerminalWidth),
			Height: uint32(conf.DefaultTerminalHeight),
			X:      uint32(conf.DefaultTerminalWidth),
			Y:      uint32(conf.DefaultTerminalHeight),
		},
	}

	// Initialize endpoint instances so clients can handle exec/shell/sftp
	// from servers (needed for multi-hop routing via slider-connect)
	sess.shellInstance = instance.New(
		&instance.Config{
			Logger:       logger,
			SessionID:    id,
			EndpointType: instance.ShellEndpoint,
		},
	)

	sess.socksInstance = instance.New(
		&instance.Config{
			Logger:       logger,
			SessionID:    id,
			EndpointType: instance.SocksEndpoint,
		},
	)

	sess.sshInstance = instance.New(
		&instance.Config{
			Logger:       logger,
			SessionID:    id,
			EndpointType: instance.SshEndpoint,
		},
	)

	// Set SSH client connection on instances if available
	if sshClient != nil {
		sess.shellInstance.SetSSHConn(sshClient)
		sess.socksInstance.SetSSHConn(sshClient)
		sess.sshInstance.SetSSHConn(sshClient)
	}

	return sess
}

// ServerSessionOptions contains optional configuration for server sessions
type ServerSessionOptions struct {
	CertificateAuthority *scrypt.CertificateAuthority
	ServerKey            ssh.Signer
	AuthOn               bool
}

// NewServerFromClientSession creates a new session for a server accepting a connection from a client (ServerRole)
func NewServerFromClientSession(
	logger *slog.Logger,
	wsConn *websocket.Conn,
	sshServerConn *ssh.ServerConn,
	sshConfig *ssh.ServerConfig,
	interp *interpreter.Interpreter,
	hostIP string,
	opts *ServerSessionOptions,
) *BidirectionalSession {
	id := atomic.AddInt64(&sessionCounter, 1)
	atomic.AddInt64(&activeCount, 1)

	logger.InfoWith("Creating server session",
		slog.F("session_id", id),
		slog.F("role", "SERVER"),
		slog.F("host_ip", hostIP))

	// Create local interpreter for local execution
	localInterp, _ := interpreter.NewInterpreter()

	sess := &BidirectionalSession{
		logger:           logger,
		sessionID:        id,
		role:             ServerRole,
		wsConn:           wsConn,
		sshServerConn:    sshServerConn,
		sshConfig:        sshConfig,
		localInterpreter: localInterp,
		peerInterpreter:  interp,
		hostIP:           hostIP,
		channels:         make([]ssh.Channel, 0),
		KeepAliveChan:    make(chan bool, 1),
		Disconnect:       make(chan bool, 1),
		active:           true,
	}

	// Initialize endpoint instances
	if opts != nil {
		sess.shellInstance = instance.New(
			&instance.Config{
				Logger:               logger,
				SessionID:            id,
				EndpointType:         instance.ShellEndpoint,
				CertificateAuthority: opts.CertificateAuthority,
			},
		)

		sess.socksInstance = instance.New(
			&instance.Config{
				Logger:       logger,
				SessionID:    id,
				EndpointType: instance.SocksEndpoint,
			},
		)

		sess.sshInstance = instance.New(
			&instance.Config{
				Logger:       logger,
				SessionID:    id,
				EndpointType: instance.SshEndpoint,
				ServerKey:    opts.ServerKey,
				AuthOn:       opts.AuthOn,
			},
		)

		// Set SSH connection on instances only if connection is not nil
		// (it will be set later in NewSSHServer after SSH handshake)
		if sshServerConn != nil {
			sess.socksInstance.SetSSHConn(sshServerConn)
			sess.shellInstance.SetSSHConn(sshServerConn)
			sess.sshInstance.SetSSHConn(sshServerConn)
		}
	}

	return sess
}

// NewServerToServerSession creates a new session for a server connecting to another server (PromiscuousRole)
func NewServerToServerSession(
	logger *slog.Logger,
	wsConn *websocket.Conn,
	sshClient *ssh.Client,
	interp *interpreter.Interpreter,
	hostIP string,
	opts *ServerSessionOptions,
) *BidirectionalSession {
	id := atomic.AddInt64(&sessionCounter, 1)
	atomic.AddInt64(&activeCount, 1)

	logger.InfoWith("Creating server-to-server session",
		slog.F("session_id", id),
		slog.F("role", "PROMISCUOUS"),
		slog.F("host_ip", hostIP))

	// Create local interpreter for local execution
	localInterp, _ := interpreter.NewInterpreter()

	sess := &BidirectionalSession{
		logger:           logger,
		sessionID:        id,
		role:             PromiscuousRole,
		wsConn:           wsConn,
		sshClient:        sshClient,
		localInterpreter: localInterp,
		peerInterpreter:  interp,
		hostIP:           hostIP,
		channels:         make([]ssh.Channel, 0),
		remoteSessions:   make(map[string]RemoteSession),
		KeepAliveChan:    make(chan bool, 1),
		Disconnect:       make(chan bool, 1),
		active:           true,
	}

	// Initialize endpoint instances
	if opts != nil {
		sess.socksInstance = instance.New(
			&instance.Config{
				Logger:       logger,
				SessionID:    id,
				EndpointType: instance.SocksEndpoint,
			},
		)

		sess.sshInstance = instance.New(
			&instance.Config{
				Logger:       logger,
				SessionID:    id,
				EndpointType: instance.SshEndpoint,
				ServerKey:    opts.ServerKey,
				AuthOn:       opts.AuthOn,
			},
		)

		sess.shellInstance = instance.New(
			&instance.Config{
				Logger:               logger,
				SessionID:            id,
				EndpointType:         instance.ShellEndpoint,
				CertificateAuthority: opts.CertificateAuthority,
			},
		)

		// Set SSH client connection on instances
		sess.socksInstance.SetSSHConn(sshClient)
		sess.shellInstance.SetSSHConn(sshClient)
		sess.sshInstance.SetSSHConn(sshClient)
	}

	return sess
}

// NewServerToListenerSession creates a new session for a server connecting to a listening client (ListenerRole)
func NewServerToListenerSession(
	logger *slog.Logger,
	wsConn *websocket.Conn,
	sshServerConn *ssh.ServerConn,
	sshConfig *ssh.ServerConfig,
	interp *interpreter.Interpreter,
	hostIP string,
	opts *ServerSessionOptions,
) *BidirectionalSession {
	id := atomic.AddInt64(&sessionCounter, 1)
	atomic.AddInt64(&activeCount, 1)

	logger.InfoWith("Creating server-to-listener session",
		slog.F("session_id", id),
		slog.F("role", "LISTENER"),
		slog.F("host_ip", hostIP))

	// Create local interpreter for local execution
	localInterp, _ := interpreter.NewInterpreter()

	sess := &BidirectionalSession{
		logger:           logger,
		sessionID:        id,
		role:             ListenerRole,
		wsConn:           wsConn,
		sshServerConn:    sshServerConn,
		sshConfig:        sshConfig,
		localInterpreter: localInterp,
		peerInterpreter:  interp,
		hostIP:           hostIP,
		channels:         make([]ssh.Channel, 0),
		KeepAliveChan:    make(chan bool, 1),
		Disconnect:       make(chan bool, 1),
		active:           true,
	}

	// Initialize endpoint instances
	if opts != nil {
		sess.socksInstance = instance.New(
			&instance.Config{
				Logger:       logger,
				SessionID:    id,
				EndpointType: instance.SocksEndpoint,
			},
		)

		sess.sshInstance = instance.New(
			&instance.Config{
				Logger:       logger,
				SessionID:    id,
				EndpointType: instance.SshEndpoint,
				ServerKey:    opts.ServerKey,
				AuthOn:       opts.AuthOn,
			},
		)

		sess.shellInstance = instance.New(
			&instance.Config{
				Logger:               logger,
				SessionID:            id,
				EndpointType:         instance.ShellEndpoint,
				CertificateAuthority: opts.CertificateAuthority,
			},
		)

		// Set SSH connection on instances only if connection is not nil
		// (it will be set later in NewSSHServer after SSH handshake)
		if sshServerConn != nil {
			sess.socksInstance.SetSSHConn(sshServerConn)
			sess.shellInstance.SetSSHConn(sshServerConn)
			sess.sshInstance.SetSSHConn(sshServerConn)
		}
	}

	return sess
}

// Close terminates the session and cleans up all resources
func (s *BidirectionalSession) Close() error {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()

	if !s.active {
		return nil // Already closed
	}

	s.logger.InfoWith("Closing session",
		slog.F("session_id", s.sessionID),
		slog.F("role", s.role.String()))
	s.active = false

	// Stop keep-alive
	if s.keepAliveOn {
		select {
		case s.KeepAliveChan <- true:
			// Successfully sent stop signal
		default:
			// Channel might be full or already closed
		}
		s.keepAliveOn = false
	}

	// Close channels
	s.channelsMutex.Lock()
	for _, ch := range s.channels {
		_ = ch.Close()
	}
	s.channelsMutex.Unlock()

	// Close SSH connections
	if s.sshClient != nil {
		_ = s.sshClient.Close()
	}
	if s.sshServerConn != nil {
		_ = s.sshServerConn.Close()
	}

	// Close WebSocket
	if s.wsConn != nil {
		_ = s.wsConn.Close()
	}

	// Stop endpoint instances (if server/promiscuous/listener)
	if s.role == ServerRole || s.role == PromiscuousRole || s.role == ListenerRole {
		if s.socksInstance != nil && s.socksInstance.IsEnabled() {
			_ = s.socksInstance.Stop()
		}
		if s.sshInstance != nil && s.sshInstance.IsEnabled() {
			_ = s.sshInstance.Stop()
		}
		if s.shellInstance != nil && s.shellInstance.IsEnabled() {
			_ = s.shellInstance.Stop()
		}
	}

	// Cancel port forwards (ClientRole)
	if s.role == ClientRole {
		s.fwdMutex.Lock()
		for _, pfc := range s.revPortFwdMap {
			if pfc.StopChan != nil {
				close(pfc.StopChan)
			}
		}
		s.fwdMutex.Unlock()
	}

	atomic.AddInt64(&activeCount, -1)
	s.logger.DebugWith("Session closed",
		slog.F("session_id", s.sessionID),
		slog.F("active_count", atomic.LoadInt64(&activeCount)))

	return nil
}

// GetActiveCount returns the number of active sessions globally
func GetActiveCount() int64 {
	return atomic.LoadInt64(&activeCount)
}

// GetTotalCount returns the total number of sessions created
func GetTotalCount() int64 {
	return atomic.LoadInt64(&sessionCounter)
}

// RegisterHandler registers a channel handler with the router
func (r *Router) RegisterHandler(channelType string, handler HandlerFunc) {
	r.handlers[channelType] = handler
}

// Route routes a channel to its handler
func (r *Router) Route(nc ssh.NewChannel) error {
	handler, exists := r.handlers[nc.ChannelType()]
	if !exists {
		_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
		r.logger.WarnWith("Unknown channel type for router",
			slog.F("type", nc.ChannelType()))
		return nil
	}
	return handler(nc)
}
