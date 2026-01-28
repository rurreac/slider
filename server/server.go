package server

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"slider/pkg/instance"
	"slider/pkg/instance/socks"
	"slider/pkg/interpreter"
	"slider/pkg/remote"
	"slider/pkg/sconn"
	"slider/pkg/scrypt"
	"slider/pkg/session"
	"slider/pkg/slog"
)

const (
	clientCertsFile = "client-certs.json"
	serverCertFile  = "server-cert.json"
)

// sessionTrack keeps track of sessions and clients
type sessionTrack struct {
	SessionCount  int64                                   // Number of Sessions created
	SessionActive int64                                   // Number of Active Sessions
	Sessions      map[int64]*session.BidirectionalSession // Map of Sessions
}

type server struct {
	*slog.Logger
	sshConf              *ssh.ServerConfig
	sessionTrack         *sessionTrack
	sessionTrackMutex    sync.Mutex
	console              Console
	serverInterpreter    *interpreter.Interpreter
	certTrack            *scrypt.CertTrack
	certTrackMutex       sync.Mutex
	certJarFile          string
	authOn               bool
	fingerprint          string
	certSaveOn           bool
	caStoreOn            bool
	keepalive            time.Duration
	urlRedirect          *url.URL
	templatePath         string
	serverHeader         string
	statusCode           int
	serverKey            ssh.Signer
	host                 string
	port                 int
	httpVersion          bool
	httpHealth           bool
	httpDirIndex         bool
	httpDirIndexPath     string
	httpConsoleOn        bool
	gateway              bool
	CertificateAuthority *scrypt.CertificateAuthority
	customProto          string
	commandRegistry      *CommandRegistry
	remoteSessions       map[string]*RemoteSessionState
	remoteSessionsMutex  sync.Mutex
	localSocks           LocalSocksServer // Local SOCKS server state
}

// LocalSocksServer tracks a standalone local SOCKS5 server with embedded mutex
type LocalSocksServer struct {
	mu     sync.Mutex
	server *socks.LocalServer
	port   int
}

type RemoteSessionState struct {
	SocksInstance *instance.Config
	SSHInstance   *instance.Config
	ShellInstance *instance.Config
}

func (s *server) NewSSHServer(biSession *session.BidirectionalSession) {
	// Determine underlying connection type
	var netConn net.Conn
	var transportType string
	if biSession.GetWebSocketConn() != nil {
		// WebSocket connection - Websocket Tunnel
		netConn = sconn.WsConnToNetConn(biSession.GetWebSocketConn())
		transportType = "Websocket"
	} else {
		// Raw connection - Beacon Tunnel
		netConn = biSession.GetRawConn()
		transportType = "Beacon Tunnel"
	}

	if netConn == nil {
		s.ErrorWith("Session has no network connection", slog.F("session_id", biSession.GetID()))
		return
	}

	s.DebugWith(
		"Established connection with client",
		slog.F("session_id", biSession.GetID()),
		slog.F("remote_addr", netConn.RemoteAddr().String()),
	)

	var sshServerConn *ssh.ServerConn
	var newChan <-chan ssh.NewChannel
	var reqChan <-chan *ssh.Request
	var err error

	sshConf := biSession.GetSSHConfig()
	// Disable authentication for listener sessions
	if biSession.GetIsListener() {
		sshConf.NoClientAuth = true
	}

	sshServerConn, newChan, reqChan, err = ssh.NewServerConn(netConn, sshConf)
	if err != nil {
		s.DErrorWith("Failed to create SSH server", slog.F("err", err))
		if biSession.GetNotifier() != nil {
			biSession.GetNotifier() <- err
		}
		return
	}
	biSession.SetSSHServerConn(sshServerConn)

	// Update endpoint instances with the SSH connection
	if biSession.GetShellInstance() != nil {
		biSession.GetShellInstance().SetSSHConn(sshServerConn)
	}
	if biSession.GetSocksInstance() != nil {
		biSession.GetSocksInstance().SetSSHConn(sshServerConn)
	}
	if biSession.GetSSHInstance() != nil {
		biSession.GetSSHInstance().SetSSHConn(sshServerConn)
	}

	// If authentication was enabled and not a listener session, save the client certificate info
	if s.authOn && !biSession.GetIsListener() {
		if certID, cErr := strconv.Atoi(sshServerConn.Permissions.Extensions["cert_id"]); cErr == nil {
			biSession.SetCertInfo(
				int64(certID),
				sshServerConn.Permissions.Extensions["fingerprint"],
			)
		}

	}

	s.DebugWith(
		fmt.Sprintf("Upgraded %s transport to SSH Connection", transportType),
		slog.F("session_id", biSession.GetID()),
		slog.F("host", biSession.GetSSHServerConn().RemoteAddr().String()),
		slog.F("client_version", biSession.GetSSHServerConn().ClientVersion()),
	)

	if biSession.GetNotifier() != nil {
		biSession.GetNotifier() <- nil
	}

	// Handle Keep Alive
	go biSession.KeepAlive(s.keepalive)

	// Inject application server BEFORE starting request handlers
	// This ensures handleClientInfo has access to server interpreter for reply
	biSession.SetApplicationServer(s)

	// Create and configure application router
	appRouter := remote.NewRouter(s.Logger)
	// Register handlers available to ALL sessions
	appRouter.RegisterHandler("slider-beacon", s.BeaconChannelHandler)

	if s.gateway {
		// Register handlers available only to Gateway sessions
		appRouter.RegisterHandler("slider-connect", remote.HandleSliderConnect)
	}
	biSession.SetRouter(appRouter)

	// Use centralized channel routing
	// Session handles all standard SSH protocol channels (shell, exec, sftp, etc.)
	// Application-specific channels (slider-connect) are delegated to injected router
	go biSession.HandleIncomingChannels(newChan)

	// Use centralized request handling
	// Session handles common protocol requests (keep-alive, tcpip-forward)
	// Application-specific requests (slider-*, client-info, etc.) are delegated to injected handler
	go biSession.HandleIncomingRequests(reqChan)

	// Block until connection closes
	_ = sshServerConn.Wait()
}

func (s *server) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key: %s", fErr)
	}

	if id, ok := scrypt.IsAllowedFingerprint(fp, s.certTrack.Certs); ok {
		s.DebugWith("Authenticated Client", slog.F("addr", conn.RemoteAddr()), slog.F("fingerprint", fp), slog.F("cert_id", id))
		return &ssh.Permissions{
			Extensions: map[string]string{
				"fingerprint": fp,
				"cert_id":     fmt.Sprintf("%d", id),
			},
		}, nil
	}
	s.WarnWith("Rejected client", slog.F("addr", conn.RemoteAddr()), slog.F("fingerprint", fp))

	return nil, fmt.Errorf("client key not authorized")
}

// GetLogger returns the server logger
func (s *server) GetLogger() *slog.Logger {
	return s.Logger
}

// GetInterpreter returns the server interpreter
func (s *server) GetInterpreter() *interpreter.Interpreter {
	return s.serverInterpreter
}

// GetSession retrieves a session by ID
// Implements session.ApplicationServer interface
func (s *server) GetSession(id int) (*session.BidirectionalSession, error) {
	s.sessionTrackMutex.Lock()
	defer s.sessionTrackMutex.Unlock()

	sess, ok := s.sessionTrack.Sessions[int64(id)]
	if !ok {
		return nil, fmt.Errorf("session %d not found", id)
	}
	return sess, nil
}

// GetAllSessions returns all local sessions sorted by ID
// Implements session.Registry interface
func (s *server) GetAllSessions() []*session.BidirectionalSession {
	s.sessionTrackMutex.Lock()
	sessions := make([]*session.BidirectionalSession, 0, len(s.sessionTrack.Sessions))
	for _, sess := range s.sessionTrack.Sessions {
		sessions = append(sessions, sess)
	}
	s.sessionTrackMutex.Unlock()

	// Sort sessions by ID to ensure deterministic order
	sort.Slice(sessions, func(i, j int) bool {
		return sessions[i].GetID() < sessions[j].GetID()
	})

	return sessions
}

// GetServerInterpreter returns the server's interpreter information
// Implements session.ServerInfo interface
func (s *server) GetServerInterpreter() *interpreter.Interpreter {
	return s.serverInterpreter
}

// IsGateway returns whether the server is in gateway mode
// Implements session.ServerInfo interface
func (s *server) IsGateway() bool {
	return s.gateway
}

// GetServerIdentity returns a unique identifier for loop detection (fingerprint:port)
// Implements session.ServerInfo interface
func (s *server) GetServerIdentity() string {
	return fmt.Sprintf("%s:%d", s.fingerprint, s.port)
}

// GetFingerprint returns the server's fingerprint for session stamping
// Implements session.ServerInfo interface
func (s *server) GetFingerprint() string {
	return s.fingerprint
}

// dropWebSocketSession removes a session from tracking
func (s *server) dropWebSocketSession(sess *session.BidirectionalSession) {
	if sess == nil {
		return
	}

	id := sess.GetID()
	if id == 0 {
		return
	}

	s.sessionTrackMutex.Lock()
	defer s.sessionTrackMutex.Unlock()

	delete(s.sessionTrack.Sessions, id)
	s.sessionTrack.SessionActive--
}

// GetKeepalive returns the keepalive duration in seconds
func (s *server) GetKeepalive() int {
	return int(s.keepalive.Seconds())
}

// isSelfConnection checks if the target host:port matches this server's listen address
// This is used to prevent a gateway server from connecting to itself
func (s *server) isSelfConnection(targetHost, targetPort string) bool {
	// Parse target port
	targetPortInt := 0
	if targetPort != "" {
		_, _ = fmt.Sscanf(targetPort, "%d", &targetPortInt)
	}

	// Check if port matches - if not, it's definitely not us
	if targetPortInt != s.port {
		return false
	}

	// Port matches - now check if host is localhost or matches our listen address
	if targetHost == "localhost" || targetHost == "127.0.0.1" || targetHost == "::1" {
		return true
	}

	// Check if target matches our specific listen address
	if s.host == "" || s.host == "0.0.0.0" || s.host == "::" {
		// We're listening on all interfaces - check if targetHost is a local IP
		return s.isLocalIP(targetHost)
	}

	// Check if target matches our specific listen address
	return targetHost == s.host
}

// isLocalIP checks if the given IP address belongs to a local interface
func (s *server) isLocalIP(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.String() == ip {
				return true
			}
		}
	}
	return false
}
