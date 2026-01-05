package session

import (
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// Role defines the operational mode of a session
type Role int

const (
	// ClientRole - Session initiated as SSH client (outgoing connection)
	// Used when: Client connecting to server
	ClientRole Role = iota

	// ServerRole - Session initiated as SSH server (incoming connection)
	// Used when: Server accepting connections from clients OR other servers
	// Note: Server must be started with --promiscuous to accept server connections
	//       Regular servers REJECT all server connections
	ServerRole

	// PromiscuousRole - Session initiated as SSH client from server's Console
	// Used when: Server executes "connect --promiscuous <address>" from Console
	// Note: Target must be a promiscuous server, source can be any server type
	//       The --promiscuous flag indicates the TARGET is promiscuous, not the source
	PromiscuousRole

	// ListenerRole - Session in listener mode (client acting as server)
	// Used when: Client started with --listener flag
	// Note: Servers connect using "connect <address>" (no --promiscuous flag)
	ListenerRole
)

// String provides human-readable role names
func (r Role) String() string {
	switch r {
	case ClientRole:
		return "CLIENT"
	case ServerRole:
		return "SERVER"
	case PromiscuousRole:
		return "PROMISCUOUS"
	case ListenerRole:
		return "LISTENER"
	default:
		return "UNKNOWN"
	}
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
	HomeDir           string
	WorkingDir        string // Current SFTP working directory (if active)
	IsListener        bool
	ConnectionAddr    string
	Path              []int64
}

// Router handles channel routing in promiscuous mode
type Router struct {
	handlers map[string]HandlerFunc
	session  *BidirectionalSession
	logger   *slog.Logger
}

// HandlerFunc is a function that handles an SSH channel
type HandlerFunc func(ssh.NewChannel) error

// certInfo stores certificate authentication information
type certInfo struct {
	fingerprint string
	id          int64
}

// ========================================
// Interfaces for Application Extensions
// ========================================

// ApplicationServer provides server-level operations needed by application-specific
// channel handlers (e.g., slider-connect). This allows session to delegate to
// server logic without creating a circular dependency.
type ApplicationServer interface {
	// GetSession retrieves a session by ID from the server's registry
	GetSession(id int) (*BidirectionalSession, error)
	// GetServerInterpreter returns the server's interpreter information
	GetServerInterpreter() *interpreter.Interpreter
	// HandleSessionsRequest handles slider-sessions requests (multi-hop listing)
	HandleSessionsRequest(req *ssh.Request, sess *BidirectionalSession) error
	// HandleForwardRequest handles slider-forward-request requests (multi-hop forwarding)
	HandleForwardRequest(req *ssh.Request, sess *BidirectionalSession) error
	// HandleEventRequest handles slider-event requests (event propagation)
	HandleEventRequest(req *ssh.Request, sess *BidirectionalSession) error
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
