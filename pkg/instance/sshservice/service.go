package sshservice

import (
	"net"
	"slider/pkg/instance/portforward"
	"slider/pkg/scrypt"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// Service represents an SSH service that handles SSH connections
type Service struct {
	logger               *slog.Logger
	sessionID            int64
	serverKey            ssh.Signer
	authOn               bool
	allowedFingerprint   string
	ptyOn                bool
	portFwdManager       *portforward.Manager
	clientVerificationFn func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)
	requestHandler       func(ssh.Channel, <-chan *ssh.Request, string)
	channelHandler       func(ssh.NewChannel, string)
}

// Config holds the configuration for creating an SSH service
type Config struct {
	Logger             *slog.Logger
	SessionID          int64
	ServerKey          ssh.Signer
	AuthOn             bool
	AllowedFingerprint string
	PtyOn              bool
	PortFwdManager     *portforward.Manager
}

// NewService creates a new SSH service
func NewService(cfg *Config) *Service {
	return &Service{
		logger:             cfg.Logger,
		sessionID:          cfg.SessionID,
		serverKey:          cfg.ServerKey,
		authOn:             cfg.AuthOn,
		allowedFingerprint: cfg.AllowedFingerprint,
		ptyOn:              cfg.PtyOn,
		portFwdManager:     cfg.PortFwdManager,
	}
}

// Type returns the service type identifier
func (s *Service) Type() string {
	return "ssh"
}

// Start implements the Service interface - handles an SSH connection
func (s *Service) Start(conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	sshConf := &ssh.ServerConfig{NoClientAuth: true}
	if s.authOn {
		sshConf.NoClientAuth = false
		sshConf.PublicKeyCallback = s.clientVerification
	}
	sshConf.AddHostKey(s.serverKey)

	sshServerConn, sshClientChannel, reqChan, cErr := ssh.NewServerConn(conn, sshConf)
	if cErr != nil {
		s.logger.ErrorWith("Failed SSH handshake",
			slog.F("session_id", s.sessionID),
			slog.F("err", cErr))
		return cErr
	}
	defer func() {
		_ = sshServerConn.Close()
		s.cancelSshRemoteFwd()
	}()

	// Service incoming SSH Request channel
	if s.requestHandler != nil {
		go s.requestHandler(nil, reqChan, "ssh-client")
	} else {
		go ssh.DiscardRequests(reqChan)
	}

	// Handle incoming SSH channels
	for nc := range sshClientChannel {
		if s.channelHandler != nil {
			go s.channelHandler(nc, nc.ChannelType())
		} else {
			// Default behavior: reject unknown channels
			s.logger.WarnWith("SSH Rejected channel type",
				slog.F("session_id", s.sessionID),
				slog.F("channel_type", nc.ChannelType()),
				slog.F("payload", nc.ExtraData()))
			_ = nc.Reject(ssh.UnknownChannelType, "")
		}
	}

	return nil
}

// Stop implements the Service interface
func (s *Service) Stop() error {
	// SSH service cleanup is handled in the defer of Start
	return nil
}

// SetRequestHandler sets the handler for SSH requests
func (s *Service) SetRequestHandler(handler func(ssh.Channel, <-chan *ssh.Request, string)) {
	s.requestHandler = handler
}

// SetChannelHandler sets the handler for SSH channels
func (s *Service) SetChannelHandler(handler func(ssh.NewChannel, string)) {
	s.channelHandler = handler
}

// clientVerification verifies the client's public key
func (s *Service) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if s.clientVerificationFn != nil {
		return s.clientVerificationFn(conn, key)
	}

	// Default verification logic
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fErr
	}

	if fp == s.allowedFingerprint {
		s.logger.DebugWith("Authenticated Client",
			slog.F("session_id", s.sessionID),
			slog.F("remote_addr", conn.RemoteAddr()),
			slog.F("fingerprint", fp))
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}

	s.logger.DebugWith("Rejected client",
		slog.F("session_id", s.sessionID),
		slog.F("remote_addr", conn.RemoteAddr()),
		slog.F("err", "bad key authentication"))

	return nil, nil
}

// cancelSshRemoteFwd cancels all SSH remote forwards
func (s *Service) cancelSshRemoteFwd() {
	if s.portFwdManager != nil {
		s.portFwdManager.CancelAllSSHRemoteForwards()
	}
}

// SetClientVerificationFn sets a custom client verification function
func (s *Service) SetClientVerificationFn(fn func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error)) {
	s.clientVerificationFn = fn
}
