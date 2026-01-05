package session

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"slider/pkg/sconn"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"

	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

// ========================================
// Channel Routing
// ========================================

// HandleIncomingChannels processes new SSH channels
// This works for ANY role - client, server, promiscuous, or listener
func (s *BidirectionalSession) HandleIncomingChannels(newChannels <-chan ssh.NewChannel) {
	for nc := range newChannels {
		go func() { _ = s.RouteChannel(nc, nc.ChannelType()) }()
	}
}

// RouteChannel routes a channel to the appropriate handler using an explicit type
func (s *BidirectionalSession) RouteChannel(nc ssh.NewChannel, channelType string) error {
	s.logger.DebugWith("Routing channel",
		slog.F("session_id", s.sessionID),
		slog.F("type", channelType),
		slog.F("role", s.role.String()))

	var err error

	switch channelType {
	case "shell":
		// All roles can handle shell (needed for multi-hop via slider-connect)
		// Security: only accepted when explicitly opened by connected peer
		err = s.HandleShell(nc)

	case "exec":
		// All roles can handle exec (needed for multi-hop via slider-connect)
		// Security: only accepted when explicitly opened by connected peer
		err = s.HandleExec(nc)

	case "sftp":
		// All roles can handle sftp (needed for multi-hop via slider-connect)
		// Security: only accepted when explicitly opened by connected peer
		err = s.HandleSFTP(nc)

	case "direct-tcpip":
		// Client and Promiscuous roles handle direct-tcpip (local port forwarding) from server
		if s.role == ClientRole || s.role == PromiscuousRole {
			err = s.HandleDirectTcpIp(nc)
		} else {
			s.logger.WarnWith("direct-tcpip not supported in this role",
				slog.F("session_id", s.sessionID),
				slog.F("role", s.role.String()))
			_ = nc.Reject(ssh.Prohibited, fmt.Sprintf("direct-tcpip not supported in %s mode", s.role.String()))
			return nil
		}

	case "socks5":
		// Client and Promiscuous roles handle socks5 requests from server
		if s.role == ClientRole || s.role == PromiscuousRole {
			err = s.HandleSocks(nc)
		} else {
			s.logger.WarnWith("socks5 not supported in this role",
				slog.F("session_id", s.sessionID),
				slog.F("role", s.role.String()))
			_ = nc.Reject(ssh.Prohibited, fmt.Sprintf("socks5 not supported in %s mode", s.role.String()))
			return nil
		}

	case "init-size":
		// All roles can handle init-size (initial terminal dimensions)
		err = s.HandleInitSize(nc)

	case "slider-connect":
		// Application-specific extension (only valid when router and server are injected)
		if s.router != nil && s.applicationServer != nil {
			err = s.router.Route(nc, s, s.applicationServer)
		} else {
			s.logger.WarnWith("slider-connect not supported (no application router/server injected)",
				slog.F("session_id", s.sessionID),
				slog.F("role", s.role.String()))
			_ = nc.Reject(ssh.Prohibited, "slider-connect not supported in this mode")
			return nil
		}

	case "session":
		// Standard SSH session - route to shell
		// All roles can handle (needed for multi-hop via slider-connect)
		err = s.HandleShell(nc)

	case "forwarded-tcpip":
		// Reverse port forwarding
		err = s.HandleForwardedTcpIp(nc)

	default:
		s.logger.WarnWith("Unknown channel type",
			slog.F("session_id", s.sessionID),
			slog.F("type", channelType))
		_ = nc.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", channelType))
		return nil
	}

	if err != nil {
		s.logger.ErrorWith("Channel handler failed",
			slog.F("session_id", s.sessionID),
			slog.F("type", channelType),
			slog.F("err", err))
	}

	return err
}

// ========================================
// Channel Handlers
// ========================================

// HandleDirectTcpIp handles direct-tcpip channels (local port forwarding)
func (s *BidirectionalSession) HandleDirectTcpIp(nc ssh.NewChannel) error {
	tcpIpMsg := &types.TcpIpChannelMsg{}
	if uErr := ssh.Unmarshal(nc.ExtraData(), tcpIpMsg); uErr != nil {
		s.logger.ErrorWith("Failed to unmarshal channel data",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("extra_data", nc.ExtraData()),
			slog.F("err", uErr))
		_ = nc.Reject(ssh.UnknownChannelType, "Failed to decode direct-tcpip data")
		return fmt.Errorf("failed to unmarshal direct-tcpip data: %w", uErr)
	}

	s.logger.DebugWith("Direct TCPIP channel request",
		slog.F("session_id", s.sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort))

	host := net.JoinHostPort(tcpIpMsg.DstHost, strconv.Itoa(int(tcpIpMsg.DstPort)))
	conn, cErr := net.Dial("tcp", host)
	if cErr != nil {
		s.logger.ErrorWith("Failed to connect to destination",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("host", host),
			slog.F("err", cErr))
		_ = nc.Reject(ssh.Prohibited, "Failed to connect to destination")
		return fmt.Errorf("failed to connect to %s: %w", host, cErr)
	}

	dChan, dReq, dErr := nc.Accept()
	if dErr != nil {
		s.logger.ErrorWith("Failed to accept channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("err", dErr))
		_ = conn.Close()
		return fmt.Errorf("failed to accept channel: %w", dErr)
	}
	go ssh.DiscardRequests(dReq)
	_, _ = sio.PipeWithCancel(dChan, conn)
	return nil
}

// HandleInitSize handles init-size channels (terminal dimensions)
func (s *BidirectionalSession) HandleInitSize(nc ssh.NewChannel) error {
	channel, requests, err := nc.Accept()
	if err != nil {
		s.logger.ErrorWith("Failed to accept channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return fmt.Errorf("failed to accept init-size channel: %w", err)
	}
	defer func() {
		_ = channel.Close()
		s.logger.DebugWith("Closing INIT-SIZE channel",
			slog.F("session_id", s.sessionID))
	}()

	payload := nc.ExtraData()
	go ssh.DiscardRequests(requests)

	s.logger.DebugWith("SSH Effective \"req-pty\" size as \"init-size\" payload",
		slog.F("session_id", s.sessionID),
		slog.F("payload", payload))

	if len(payload) > 0 {
		var winSize types.TermDimensions
		if jErr := json.Unmarshal(payload, &winSize); jErr != nil {
			s.logger.ErrorWith("Failed to unmarshal terminal size payload",
				slog.F("session_id", s.sessionID),
				slog.F("err", jErr))
			return fmt.Errorf("failed to unmarshal terminal size: %w", jErr)
		}
		s.SetInitTermSize(winSize)
	}
	return nil
}

// HandleSocks handles socks5 channels
func (s *BidirectionalSession) HandleSocks(nc ssh.NewChannel) error {
	socksChan, req, aErr := nc.Accept()
	if aErr != nil {
		s.logger.ErrorWith("Failed to accept channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", nc.ChannelType()),
			slog.F("err", aErr))
		return fmt.Errorf("failed to accept socks5 channel: %w", aErr)
	}
	defer func() {
		s.logger.DebugWith("Closing Socks Channel",
			slog.F("session", s.sessionID))
		_ = socksChan.Close()
	}()
	go ssh.DiscardRequests(req)

	// Create a net.Conn from the SSH channel
	socksConn := sconn.SSHChannelToNetConn(socksChan)
	defer func() { _ = socksConn.Close() }()

	// Set up configuration for the SOCKS5 server
	socksConf := &socks5.Config{
		// Disable logging
		Logger: slog.NewDummyLog(),
	}

	// Create a new SOCKS5 server
	server, err := socks5.New(socksConf)
	if err != nil {
		s.logger.ErrorWith("Failed to create SOCKS5 server",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return fmt.Errorf("failed to create SOCKS5 server: %w", err)
	}

	// Serve the connection
	s.logger.DebugWith("Starting SOCKS5 server on connection",
		slog.F("session_id", s.sessionID))
	if sErr := server.ServeConn(socksConn); sErr != nil {
		// Logging Errors as Debug as most of them are:
		// - Failed to handle request: EOF
		// - read: connection reset by peer
		s.logger.DebugWith("Error in SOCKS5 server",
			slog.F("session_id", s.sessionID),
			slog.F("err", sErr))
	}

	s.logger.DebugWith("SOCKS5 server connection closed",
		slog.F("session_id", s.sessionID))
	return nil
}

// HandleForwardedTcpIp handles forwarded-tcpip channels (reverse port forwarding)
// This is called when a remote side opens a forwarded-tcpip channel to us
func (s *BidirectionalSession) HandleForwardedTcpIp(nc ssh.NewChannel) error {
	// Delegate to the role-specific handler
	// This method is already implemented in client_mode.go and handles
	// forwarded-tcpip appropriately based on the session's role
	s.HandleForwardedTcpIpChannel(nc)
	return nil
}
