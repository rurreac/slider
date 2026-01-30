package session

import (
	"io"
	"os"
	"slider/pkg/slog"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// HandleSFTP processes an SFTP channel for ANY role
func (s *BidirectionalSession) HandleSFTP(nc ssh.NewChannel) error {
	s.logger.DebugWith("Handling SFTP channel",
		slog.F("session_id", s.sessionID),
		slog.F("role", s.role.String()))

	sftpChan, requests, err := nc.Accept()
	if err != nil {
		s.logger.ErrorWith("Failed to accept SFTP channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}
	defer func() {
		s.logger.DebugWith("Closing SFTP channel",
			slog.F("session_id", s.sessionID))
		_ = sftpChan.Close()
	}()

	s.AddChannel(sftpChan)

	// Handle channel requests in the background
	go ssh.DiscardRequests(requests)

	// Create SFTP server options
	var serverOptions []sftp.ServerOption
	if s.logger.IsDebug() {
		serverOptions = append(serverOptions, sftp.WithDebug(os.Stderr))
	}

	// Determine working directory
	if s.sftpWorkingDir != "" {
		serverOptions = append(serverOptions,
			sftp.WithServerWorkingDirectory(s.sftpWorkingDir))
	}

	// Create the SFTP server
	s.logger.DebugWith("Initializing SFTP server",
		slog.F("session_id", s.sessionID))

	server, err := sftp.NewServer(sftpChan, serverOptions...)
	if err != nil {
		s.logger.ErrorWith("Failed to create SFTP server",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}
	defer func() { _ = server.Close() }()

	// Serve SFTP requests
	if err := server.Serve(); err != nil && err != io.EOF {
		s.logger.ErrorWith("SFTP server error",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}

	s.logger.DebugWith("SFTP session completed",
		slog.F("session_id", s.sessionID))
	return nil
}
