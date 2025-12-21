package remote

import (
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// Session defines the required interface for a session by channel handlers
type Session interface {
	GetLogger() *slog.Logger
	GetID() int64
	AddSessionChannel(ssh.Channel)
	GetSSHConn() ssh.Conn
	GetSSHClient() *ssh.Client
	HandleForwardedTcpIpChannel(nc ssh.NewChannel)
	SetInitTermSize(types.TermDimensions)
	GetInitTermSize() types.TermDimensions
}

// Server defines the required interface for the server by channel handlers
type Server interface {
	GetLogger() *slog.Logger
	GetInterpreter() *interpreter.Interpreter
	GetSession(id int) (Session, error)
	GetKeepalive() int // actually time.Duration but let's see
}
