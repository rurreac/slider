package session

import (
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// Role defines the security intent of a session
type Role int

const (
	// AgentConnector - Target (offers shell) that initiated the connection
	AgentConnector Role = iota
	// AgentListener - Target (offers shell) that accepted the connection
	AgentListener
	// OperatorConnector - Controller (uses shell) that initiated the connection
	OperatorConnector
	// OperatorListener - Controller (uses shell) that accepted the connection
	OperatorListener
	// GatewayConnector - Relay (routes traffic) that initiated the connection
	GatewayConnector
	// GatewayListener - Relay (routes traffic) that accepted the connection
	GatewayListener
)

// String provides human-readable role names
func (r Role) String() string {
	switch r {
	case AgentConnector:
		return "agent/c"
	case AgentListener:
		return "agent/l"
	case OperatorConnector:
		return "operator/c"
	case OperatorListener:
		return "operator/l"
	case GatewayConnector:
		return "gateway/c"
	case GatewayListener:
		return "gateway/l"
	default:
		return "unknown"
	}
}

// Role helper methods

func (r Role) IsAgent() bool {
	return r == AgentConnector || r == AgentListener
}

func (r Role) IsOperator() bool {
	return r == OperatorConnector || r == OperatorListener
}

func (r Role) IsGateway() bool {
	return r == GatewayConnector || r == GatewayListener
}

func (r Role) IsConnector() bool {
	return r == AgentConnector || r == OperatorConnector || r == GatewayConnector
}

// RevPortControl tracks a reverse port forward
type RevPortControl struct {
	Port        uint32
	BindAddress string
	StopChan    chan bool
}

// RemoteSession represents a session on a connected server
type RemoteSession struct {
	ID                int64
	ServerFingerprint string
	User              string
	Host              string
	System            string
	Arch              string
	Role              string
	HomeDir           string
	WorkingDir        string // Current SFTP working directory (if active)
	SliderDir         string // Binary path
	LaunchDir         string // Launch path
	IsConnector       bool
	IsPromiscuous     bool
	ConnectionAddr    string
	Path              []int64
}

// certInfo stores certificate authentication information
type certInfo struct {
	fingerprint string
	id          int64
}

// ========================================
// Interfaces for Application Extensions
// ========================================

// SessionRegistry provides access to the server's session registry
type SessionRegistry interface {
	// GetSession retrieves a session by ID from the server's registry
	GetSession(id int) (*BidirectionalSession, error)
	// GetAllSessions returns all sessions from the server's registry
	GetAllSessions() []*BidirectionalSession
}

// ServerInfo provides server-level metadata
type ServerInfo interface {
	// GetServerInterpreter returns the server's interpreter information
	GetServerInterpreter() *interpreter.Interpreter
	// IsPromiscuous returns whether the local server is in promiscuous mode
	IsPromiscuous() bool
	// GetServerIdentity returns a unique identifier for loop detection (fingerprint:port)
	GetServerIdentity() string
	// GetFingerprint returns the server's fingerprint for session stamping
	GetFingerprint() string
}

// ApplicationServer combines all server capabilities needed by sessions
// This allows session to delegate to server logic without creating a circular dependency.
type ApplicationServer interface {
	SessionRegistry
	ServerInfo
}

// Session interface for use by remote handlers
// This allows handlers to access session methods without depending on the concrete type
type Session interface {
	GetID() int64
	GetLogger() *slog.Logger
	GetSSHConn() ssh.Conn
	GetSSHClient() *ssh.Client
	GetConnection() ssh.Conn // Alias for GetSSHConn for backward compatibility
	AddChannel(ch ssh.Channel)
	AddSessionChannel(ch ssh.Channel) // Alias for AddChannel for backward compatibility
	GetInterpreter() *interpreter.Interpreter
	HandleForwardedTcpIpChannel(nc ssh.NewChannel)
	SetInitTermSize(types.TermDimensions)
	GetInitTermSize() types.TermDimensions
	ReplyConnRequest(req *ssh.Request, ok bool, payload []byte) error
	AddReversePortForward(port uint32, bindAddress string, stopChan chan bool) error
	RemoveReversePortForward(port uint32) error
	GetReversePortForwards() map[uint32]*RevPortControl
	RouteChannel(nc ssh.NewChannel, channelType string) error
}

// ApplicationRouter handles application-specific channel types (e.g., slider-connect)
// This interface allows session to delegate to application logic without circular dependencies
type ApplicationRouter interface {
	// Route handles an incoming channel using application-specific logic
	// It receives the channel, the session, and the server for context
	Route(nc ssh.NewChannel, sess Session, srv ApplicationServer) error
}

// ApplicationRequestHandler handles application-specific global requests (e.g., slider-sessions, window-size)
// This interface allows session to delegate application-specific requests without circular dependencies
type ApplicationRequestHandler interface {
	// HandleRequest processes an application-specific SSH global request
	// It receives the request and the session, and should return true if handled
	HandleRequest(req *ssh.Request, sess Session) bool
}
