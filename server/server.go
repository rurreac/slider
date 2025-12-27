package server

import (
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
	"slider/server/remote"
)

const (
	clientCertsFile = "client-certs.json"
	serverCertFile  = "server-cert.json"
)

// sessionTrack keeps track of sessions and clients
type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
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
	promiscuous          bool
	CertificateAuthority *scrypt.CertificateAuthority
	customProto          string
	commandRegistry      *CommandRegistry
	remoteSessions       map[string]*RemoteSessionState
	remoteSessionsMutex  sync.Mutex
}

type RemoteSessionState struct {
	SocksInstance *instance.Config
	SSHInstance   *instance.Config
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
func (s *server) GetSession(id int) (remote.Session, error) {
	sess, err := s.getSession(id)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

// GetKeepalive returns the keepalive duration in seconds
func (s *server) GetKeepalive() int {
	return int(s.keepalive.Seconds())
}

// isSelfConnection checks if the target host:port matches this server's listen address
// This is used to prevent a promiscuous server from connecting to itself
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
