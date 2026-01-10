package session

import (
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// BidirectionalSession represents a session that can act as client or server.
// This single type replaces both client.Session and server.Session.
type BidirectionalSession struct {
	// ========================================
	// Core Identity
	// ========================================
	logger    *slog.Logger
	sessionID int64
	role      Role
	peerRole  Role

	// ========================================
	// Network Connections
	// ========================================
	wsConn *websocket.Conn // WebSocket underlying connection

	// SSH Connections - exactly ONE will be set based on role:
	// - AgentRole/OperatorRole (Initiator): sshClient is set
	// - OperatorRole/GatewayRole/AgentRole (Acceptor): sshServerConn is set
	sshClient     *ssh.Client       // When acting as SSH client
	sshServerConn *ssh.ServerConn   // When acting as SSH server
	sshConfig     *ssh.ServerConfig // Server configuration (Acceptor roles only)

	// ========================================
	// Session State
	// ========================================
	localInterpreter *interpreter.Interpreter // Host system info for local process execution
	peerInterpreter  *interpreter.Interpreter // Remote system info received from peer
	initTermSize     types.TermDimensions
	isListener       bool // Whether this session is to/from a listener client
	isGateway        bool // Whether the peer node is in gateway mode

	// Channel tracking
	channels      []ssh.Channel
	channelsMutex sync.RWMutex

	// ========================================
	// Lifecycle Management
	// ========================================
	KeepAliveChan chan bool
	keepAliveOn   bool
	Disconnect    chan bool // Exported for compatibility
	active        bool
	sessionMutex  sync.Mutex

	// ========================================
	// Feature-Specific State
	// ========================================

	// Port Forwarding (used in AgentRole)
	revPortFwdMap map[uint32]*RevPortControl
	fwdMutex      sync.RWMutex

	// Endpoint Instances (OperatorRole, GatewayRole, AgentRole)
	socksInstance *instance.Config
	sshInstance   *instance.Config
	shellInstance *instance.Config

	// Application Extensions (OperatorRole, GatewayRole)
	// Router handles application-specific channels (e.g., slider-connect)
	router ApplicationRouter
	// ApplicationServer provides access to server-level operations
	// Only injected for gateway servers - presence enables multi-hop features
	applicationServer ApplicationServer
	// RequestHandler handles application-specific SSH global requests (deprecated, kept for backward compatibility)
	requestHandler ApplicationRequestHandler

	// SFTP State (OperatorRole, GatewayRole)
	sftpHistory    *CustomHistory // Save history within the session
	sftpWorkingDir string         // Save Working dir for the next run

	// Server-specific metadata
	hostIP     string
	certInfo   certInfo
	notifier   chan error
	serverAddr string // For client role

	// ========================================
	// Remote Session Tracking (GatewayRole/AgentRole if gateway)
	// ========================================
	remoteSessions      map[string]RemoteSession
	remoteSessionsMutex sync.RWMutex
}

// GetID returns the session ID
func (s *BidirectionalSession) GetID() int64 {
	return s.sessionID
}

// GetRole returns the session role
func (s *BidirectionalSession) GetRole() Role {
	return s.role
}

// SetRole updates the session role
func (s *BidirectionalSession) SetRole(role Role) {
	s.role = role
}

// GetPeerRole returns the role of the peer
func (s *BidirectionalSession) GetPeerRole() Role {
	return s.peerRole
}

// SetPeerRole updates the peer role
func (s *BidirectionalSession) SetPeerRole(role Role) {
	s.peerRole = role
}

// GetLogger returns the session logger
func (s *BidirectionalSession) GetLogger() *slog.Logger {
	return s.logger
}

// GetHostIP returns the session host IP
func (s *BidirectionalSession) GetHostIP() string {
	return s.hostIP
}

// IsActive returns whether the session is active
func (s *BidirectionalSession) IsActive() bool {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.active
}

// GetIsListener returns whether this is a listener session
func (s *BidirectionalSession) GetIsListener() bool {
	return s.isListener
}

// SetIsListener sets whether this is a listener session
func (s *BidirectionalSession) SetIsListener(isListener bool) {
	s.isListener = isListener
}

// GetIsGateway returns whether the peer is in gateway mode
func (s *BidirectionalSession) GetIsGateway() bool {
	return s.isGateway
}

// SetIsGateway sets whether the peer is in gateway mode
func (s *BidirectionalSession) SetIsGateway(isGateway bool) {
	s.isGateway = isGateway
}

// GetSSHConn returns the SSH connection (abstracted)
func (s *BidirectionalSession) GetSSHConn() ssh.Conn {
	if s.sshClient != nil {
		return s.sshClient.Conn
	}
	return s.sshServerConn
}

// GetSSHClient returns the SSH client (Initiator roles only)
func (s *BidirectionalSession) GetSSHClient() *ssh.Client {
	return s.sshClient
}

// GetWebSocketConn returns the WebSocket connection
func (s *BidirectionalSession) GetWebSocketConn() *websocket.Conn {
	return s.wsConn
}

// GetInterpreter returns the remote session (peer) interpreter info
func (s *BidirectionalSession) GetInterpreter() *interpreter.Interpreter {
	return s.peerInterpreter
}

// GetLocalInterpreter returns the host (local) interpreter info
func (s *BidirectionalSession) GetLocalInterpreter() *interpreter.Interpreter {
	return s.localInterpreter
}

// SetInitTermSize sets the initial terminal size
func (s *BidirectionalSession) SetInitTermSize(size types.TermDimensions) {
	s.sessionMutex.Lock()
	s.initTermSize = size
	s.sessionMutex.Unlock()
}

// GetInitTermSize gets the initial terminal size
func (s *BidirectionalSession) GetInitTermSize() types.TermDimensions {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.initTermSize
}

// IsPtyOn returns whether PTY is enabled on the peer system
func (s *BidirectionalSession) IsPtyOn() bool {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	if s.peerInterpreter == nil {
		return false
	}
	return s.peerInterpreter.PtyOn
}

// AddChannel registers a channel with the session
func (s *BidirectionalSession) AddChannel(ch ssh.Channel) {
	s.channelsMutex.Lock()
	defer s.channelsMutex.Unlock()
	s.channels = append(s.channels, ch)
}

// GetChannels returns all registered channels
func (s *BidirectionalSession) GetChannels() []ssh.Channel {
	s.channelsMutex.RLock()
	defer s.channelsMutex.RUnlock()

	result := make([]ssh.Channel, len(s.channels))
	copy(result, s.channels)
	return result
}

// GetCertInfo returns certificate information
func (s *BidirectionalSession) GetCertInfo() (id int64, fingerprint string) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.certInfo.id, s.certInfo.fingerprint
}
