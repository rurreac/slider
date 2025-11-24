package server

import (
	"fmt"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
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
	certSaveOn           bool
	caStoreOn            bool
	keepalive            time.Duration
	urlRedirect          *url.URL
	templatePath         string
	serverHeader         string
	statusCode           int
	serverKey            ssh.Signer
	httpVersion          bool
	httpHealth           bool
	CertificateAuthority *scrypt.CertificateAuthority
	customProto          string
	commandRegistry      *CommandRegistry
	sftpCommandRegistry  *CommandRegistry
	sftpContext          *SftpCommandContext
}

func (s *server) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if id, ok := scrypt.IsAllowedFingerprint(fp, s.certTrack.Certs); ok {
		s.Debugf("Authenticated Client %s fingerprint: %s", conn.RemoteAddr(), fp)
		return &ssh.Permissions{
			Extensions: map[string]string{
				"fingerprint": fp,
				"cert_id":     fmt.Sprintf("%d", id),
			},
		}, nil
	}
	s.Warnf("Rejected client %s, due to bad key authentication", conn.RemoteAddr())

	return nil, fmt.Errorf("client key not authorized")
}
