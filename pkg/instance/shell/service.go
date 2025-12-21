package shell

import (
	"encoding/json"
	"net"
	"os"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// Service represents a Shell service that handles shell connections
type Service struct {
	logger         *slog.Logger
	sessionID      int64
	opener         ChannelOpener
	envVarList     []struct{ Key, Value string }
	interactiveOn  bool
}

// ChannelOpener defines the interface for opening SSH channels and sending requests
type ChannelOpener interface {
	OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

// NewService creates a new Shell service
func NewService(logger *slog.Logger, sessionID int64, opener ChannelOpener) *Service {
	return &Service{
		logger:        logger,
		sessionID:     sessionID,
		opener:        opener,
		envVarList:    make([]struct{ Key, Value string }, 0),
		interactiveOn: false,
	}
}

// Type returns the service type identifier
func (s *Service) Type() string {
	return "shell"
}

// Start implements the Service interface - handles a shell connection
func (s *Service) Start(conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	width, height, tErr := term.GetSize(int(os.Stdout.Fd()))
	if tErr != nil {
		s.logger.ErrorWith("Failed to get terminal size",
			slog.F("session_id", s.sessionID),
			slog.F("err", tErr))
		return tErr
	}

	initSize, uErr := json.Marshal(
		&types.TermDimensions{
			Width:  uint32(width),
			Height: uint32(height),
		},
	)
	if uErr != nil {
		s.logger.ErrorWith("Failed to marshal init terminal size",
			slog.F("session_id", s.sessionID),
			slog.F("err", uErr))
		return uErr
	}

	// Send message with initial size
	initChan, reqs, oErr := s.opener.OpenChannel("init-size", initSize)
	if oErr != nil {
		s.logger.ErrorWith("Failed to open channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", "init-size"),
			slog.F("err", oErr))
		return oErr
	}
	go ssh.DiscardRequests(reqs)
	_ = initChan.Close()

	winChange := make(chan []byte, 10)
	defer close(winChange)
	envChange := make(chan []byte, 10)
	defer close(envChange)

	return s.interactiveConnPipe(conn, "shell", nil, winChange, envChange)
}

// Stop implements the Service interface
func (s *Service) Stop() error {
	// Shell service doesn't maintain persistent state that needs cleanup
	return nil
}

// SetEnvVarList sets the environment variable list for the service
func (s *Service) SetEnvVarList(evl []struct{ Key, Value string }) {
	s.envVarList = evl
}

// SetInteractiveOn sets whether interactive mode is enabled
func (s *Service) SetInteractiveOn(interactiveOn bool) {
	s.interactiveOn = interactiveOn
}

// interactiveConnPipe is extracted from instance.go to handle shell connection piping
func (s *Service) interactiveConnPipe(conn net.Conn, channelType string, payload []byte, winChange chan []byte, envChange chan []byte) error {
	sliderClientChannel, shellRequests, oErr := s.opener.OpenChannel(channelType, payload)
	if oErr != nil {
		s.logger.ErrorWith("Failed to open SSH channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channelType),
			slog.F("err", oErr))
		return oErr
	}
	defer func() { _ = sliderClientChannel.Close() }()

	// Handle window-change events
	go func() {
		for sizeBytes := range winChange {
			_, wErr := sliderClientChannel.SendRequest("window-change", true, sizeBytes)
			if wErr != nil {
				s.logger.ErrorWith("Failed to send request",
					slog.F("session_id", s.sessionID),
					slog.F("request_type", "window-change"),
					slog.F("err", wErr))
			}
		}
	}()

	var envCloser struct{ Key, Value string }
	envCloser.Key = "SLIDER_ENV"
	envCloser.Value = "true"
	envCloserBytes := ssh.Marshal(envCloser)
	envChange <- envCloserBytes

	// Handle environment variable events
	go func() {
		for envVarBytes := range envChange {
			_, eErr := sliderClientChannel.SendRequest("env", true, envVarBytes)
			if eErr != nil {
				s.logger.ErrorWith("Failed to send request",
					slog.F("session_id", s.sessionID),
					slog.F("request_type", "env"),
					slog.F("err", eErr))
			}
		}
	}()

	// Handle requests from the SSH channel
	go ssh.DiscardRequests(shellRequests)

	// Pipe SSH channel with connection
	_, _ = sio.PipeWithCancel(conn, sliderClientChannel)

	return nil
}
