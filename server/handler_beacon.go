package server

import (
	"net"
	"slider/pkg/sconn"
	"slider/pkg/session"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// BeaconChannelHandler handles "slider-beacon" SSH channels
// It wraps the channel as a net.Conn and initiates a new server session
func (s *server) BeaconChannelHandler(nc ssh.NewChannel, sess session.Session, srv session.ApplicationServer) error {
	channel, reqs, err := nc.Accept()
	if err != nil {
		return err
	}
	go ssh.DiscardRequests(reqs)

	// Wrap channel as net.Conn
	conn := sconn.SSHChannelToNetConn(channel)

	// Handle as new session
	go s.HandleBeaconConnect(conn)

	return nil
}

// HandleBeaconConnect handles incoming Beacon connections tunneled via SSH channels
func (s *server) HandleBeaconConnect(conn net.Conn) {
	s.DebugWith("Processing new Beacon connection",
		slog.F("remote_addr", conn.RemoteAddr().String()))

	// Create session for Beacon agent
	// We pass nil for wsConn since this is a raw connection
	// We will set rawConn manually
	remoteAddr := conn.RemoteAddr().String()
	opts := &session.ServerSessionOptions{
		CertificateAuthority: s.CertificateAuthority,
		ServerKey:            s.serverKey,
		AuthOn:               s.authOn,
	}

	biSession := session.NewServerFromClientSession(
		s.Logger,
		nil,                 // No WebSocket
		nil,                 // sshServerConn set by NewSSHServer
		s.sshConf,           // SSH config
		s.serverInterpreter, // Server interpreter
		remoteAddr,
		opts,
	)

	// Set Beacon specific fields
	biSession.SetRawConn(conn)
	// Set roles
	biSession.SetRole(session.OperatorListener)
	biSession.SetPeerRole(session.AgentConnector)

	// Add to session track
	s.sessionTrackMutex.Lock()
	s.sessionTrack.Sessions[biSession.GetID()] = biSession
	s.sessionTrack.SessionCount = biSession.GetID()
	s.sessionTrack.SessionActive++
	s.sessionTrackMutex.Unlock()

	defer func() {
		s.dropWebSocketSession(biSession)
		s.NotifyUpstreamDisconnect(biSession.GetID())
	}()

	s.NewSSHServer(biSession)
}
