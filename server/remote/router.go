package remote

import (
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// Handler is a function that handles an SSH channel
type Handler func(nc ssh.NewChannel, sess Session, srv Server) error

// Router routes incoming SSH channels to appropriate handlers
type Router struct {
	handlers map[string]Handler
	logger   *slog.Logger
}

// NewRouter creates a new channel router
func NewRouter(logger *slog.Logger) *Router {
	return &Router{
		handlers: make(map[string]Handler),
		logger:   logger,
	}
}

// RegisterHandler registers a handler for a specific channel type
func (r *Router) RegisterHandler(channelType string, handler Handler) {
	r.handlers[channelType] = handler
}

// Route routes an incoming channel to the appropriate handler
func (r *Router) Route(nc ssh.NewChannel, sess Session, srv Server) error {

	channelType := nc.ChannelType()

	handler, exists := r.handlers[channelType]
	if !exists {
		r.logger.DebugWith("Rejected channel",
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
