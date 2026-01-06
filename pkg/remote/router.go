package remote

import (
	"slider/pkg/session"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// Handler is a function that handles an SSH channel with application context
type Handler func(nc ssh.NewChannel, sess session.Session, srv session.ApplicationServer) error

// Router routes application-specific SSH channels (e.g., slider-connect)
// It implements session.ApplicationRouter interface
type Router struct {
	handlers map[string]Handler
	logger   *slog.Logger
}

// NewRouter creates a new application router
func NewRouter(logger *slog.Logger) *Router {
	return &Router{
		handlers: make(map[string]Handler),
		logger:   logger,
	}
}

// RegisterHandler registers a handler for a specific application channel type
func (r *Router) RegisterHandler(channelType string, handler Handler) {
	r.handlers[channelType] = handler
}

// Route implements session.ApplicationRouter interface
// It routes application-specific channels to registered handlers
func (r *Router) Route(nc ssh.NewChannel, sess session.Session, srv session.ApplicationServer) error {
	channelType := nc.ChannelType()

	handler, exists := r.handlers[channelType]
	if !exists {
		r.logger.DebugWith("Rejected application channel",
			slog.F("channel_type", channelType))
		if err := nc.Reject(ssh.UnknownChannelType, ""); err != nil {
			r.logger.DErrorWith("Failed to reject channel",
				slog.F("channel_type", channelType),
				slog.F("err", err))
		}
		return nil
	}

	return handler(nc, sess, srv)
}
