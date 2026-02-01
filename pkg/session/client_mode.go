package session

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// Methods specific to AgentRole (clients/listeners that offer interactive access)

// AddReversePortForward adds a reverse port forward (ClientRole only)
// This is used when the server requests a reverse port forward from the client
func (s *BidirectionalSession) AddReversePortForward(
	port uint32,
	bindAddress string,
	stopChan chan bool,
) error {
	if !s.role.IsAgent() {
		return fmt.Errorf("reverse port forwarding only available in client mode")
	}

	s.fwdMutex.Lock()
	defer s.fwdMutex.Unlock()

	// Lazy initialization
	if s.revPortFwdMap == nil {
		s.revPortFwdMap = make(map[uint32]*RevPortControl)
	}

	s.revPortFwdMap[port] = &RevPortControl{
		Port:        port,
		BindAddress: bindAddress,
		StopChan:    stopChan,
	}

	s.logger.InfoWith("Added reverse port forward",
		slog.F("session_id", s.sessionID),
		slog.F("port", port),
		slog.F("bind_address", bindAddress))
	return nil
}

// RemoveReversePortForward removes a reverse port forward
func (s *BidirectionalSession) RemoveReversePortForward(port uint32) error {
	if !s.role.IsAgent() {
		return fmt.Errorf("reverse port forwarding only available in client mode")
	}

	s.fwdMutex.Lock()
	defer s.fwdMutex.Unlock()

	pfc, exists := s.revPortFwdMap[port]
	if !exists {
		return fmt.Errorf("port forward for port %d not found", port)
	}

	if pfc.StopChan != nil {
		close(pfc.StopChan)
	}

	delete(s.revPortFwdMap, port)
	s.logger.InfoWith("Removed reverse port forward",
		slog.F("session_id", s.sessionID),
		slog.F("port", port))

	return nil
}

// GetReversePortForwards returns all active reverse port forwards
func (s *BidirectionalSession) GetReversePortForwards() map[uint32]*RevPortControl {
	s.fwdMutex.RLock()
	defer s.fwdMutex.RUnlock()

	// Return empty map if not initialized
	if s.revPortFwdMap == nil {
		return make(map[uint32]*RevPortControl)
	}

	result := make(map[uint32]*RevPortControl)
	for k, v := range s.revPortFwdMap {
		result[k] = v
	}
	return result
}

// HandleForwardedTCPIPChannel handles incoming forwarded-tcpip channels
// Called when a reverse port forward connection arrives
func (s *BidirectionalSession) HandleForwardedTCPIPChannel(nc ssh.NewChannel) {
	var tcpIpMsg types.TcpIpChannelMsg
	customMsg := &types.CustomTcpIpChannelMsg{}

	// Assume CustomTcpIpChannelMsg message format first, otherwise fallback to SSH wire format
	if jErr := json.Unmarshal(nc.ExtraData(), customMsg); jErr == nil && customMsg.TcpIpChannelMsg != nil {
		// CustomTcpIpChannelMsg format - internally handled reverse port forward
		tcpIpMsg = *customMsg.TcpIpChannelMsg
	} else {
		// SSH wire format - reverse port forward from external ssh connection
		if uErr := ssh.Unmarshal(nc.ExtraData(), &tcpIpMsg); uErr != nil {
			s.logger.ErrorWith("Failed to unmarshal forwarded-tcpip data",
				slog.F("session_id", s.sessionID),
				slog.F("err", uErr))
			_ = nc.Reject(ssh.UnknownChannelType, "Failed to decode forwarded-tcpip data")
			return
		}
	}

	s.logger.DebugWith("Forwarded-tcpip channel request",
		slog.F("session_id", s.sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort),
		slog.F("src_host", tcpIpMsg.SrcHost),
		slog.F("src_port", tcpIpMsg.SrcPort),
		slog.F("protocol", customMsg.Protocol))

	channel, requests, aErr := nc.Accept()
	if aErr != nil {
		s.logger.ErrorWith("Failed to accept forwarded-tcpip channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", aErr))
		return
	}
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)

	protocol := customMsg.Protocol

	// Check if this is a Server-managed reverse forward (e.g. initiated by console portfwd -R)
	if s.sshInstance != nil {
		mapping, mErr := s.sshInstance.GetRemotePortMapping(protocol, tcpIpMsg.SrcPort)
		if mErr != nil {
			s.logger.ErrorWith("Failed to find mapping for forwarded-tcpip",
				slog.F("session_id", s.sessionID),
				slog.F("src_port", tcpIpMsg.SrcPort),
				slog.F("protocol", protocol))
			return
		}

		s.logger.DebugWith("Directly handling forwarded-tcpip channel",
			slog.F("session_id", s.sessionID),
			slog.F("src_port", tcpIpMsg.SrcPort),
			slog.F("protocol", protocol))

		// For standard SSH reverse forwards, the payload contains the "originator" (src) and "connected" (dst) addresses.
		// BUT the "dst" in the payload is the BIND address (e.g. 0.0.0.0 or localhost on the client).
		// We need to route to the TARGET address configured in the Manager/Console.
		// The mapping contains the configured destination.
		dstHost := mapping.TcpIpChannelMsg.DstHost
		dstPort := mapping.TcpIpChannelMsg.DstPort
		host := net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))

		conn, cErr := net.Dial(protocol, host)
		if cErr != nil {
			s.logger.ErrorWith("Failed to connect to local destination",
				slog.F("session_id", s.sessionID),
				slog.F("host", host),
				slog.F("protocol", protocol),
				slog.F("err", cErr))
			return
		}
		defer func() { _ = conn.Close() }()

		s.logger.DebugWith("Bridged forwarded-tcpip channel",
			slog.F("session_id", s.sessionID),
			slog.F("target", host),
			slog.F("protocol", protocol))

		// Pipe the SSH channel to the local connection
		_, _ = sio.PipeWithCancel(channel, conn)
		return
	}

	// Fallback for non-server managed sessions (e.g. direct client-to-client or legacy)
	// This path relies on the payload containing the correct destination.
	host := net.JoinHostPort(tcpIpMsg.DstHost, strconv.Itoa(int(tcpIpMsg.DstPort)))
	conn, cErr := net.Dial(protocol, host)
	if cErr != nil {
		s.logger.ErrorWith("Failed to connect to local destination",
			slog.F("session_id", s.sessionID),
			slog.F("host", host),
			slog.F("protocol", protocol),
			slog.F("err", cErr))
		return
	}
	defer func() { _ = conn.Close() }()

	_, _ = sio.PipeWithCancel(channel, conn)

	s.logger.DebugWith("Completed forwarded-tcpip channel",
		slog.F("session_id", s.sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort),
		slog.F("protocol", protocol))
}

// HandleForwardedUDPChannel handles incoming forwarded-udp channels
// Called when a reverse port forward connection arrives for UDP
func (s *BidirectionalSession) HandleForwardedUDPChannel(nc ssh.NewChannel) {
	var tcpIpMsg types.TcpIpChannelMsg
	customMsg := &types.CustomTcpIpChannelMsg{}

	// UDP is internally initiated through Console (always CustomTcpIpChannelMsg format)
	if jErr := json.Unmarshal(nc.ExtraData(), customMsg); jErr == nil && customMsg.TcpIpChannelMsg != nil {
		tcpIpMsg = *customMsg.TcpIpChannelMsg
	} else {
		s.logger.ErrorWith("Failed to unmarshal forwarded-udp data",
			slog.F("session_id", s.sessionID),
			slog.F("err", jErr))
		_ = nc.Reject(ssh.UnknownChannelType, "Failed to decode forwarded-udp data")
		return
	}

	protocol := customMsg.Protocol

	s.logger.DebugWith("Forwarded-udp channel request",
		slog.F("session_id", s.sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort),
		slog.F("src_host", tcpIpMsg.SrcHost),
		slog.F("src_port", tcpIpMsg.SrcPort),
		slog.F("protocol", protocol))

	channel, requests, aErr := nc.Accept()
	if aErr != nil {
		s.logger.ErrorWith("Failed to accept forwarded-udp channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", aErr))
		return
	}
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)

	// Check if this is a Server-managed reverse forward (e.g. initiated by console portfwd -R)
	if s.sshInstance != nil {
		mapping, mErr := s.sshInstance.GetRemotePortMapping(protocol, tcpIpMsg.SrcPort)
		if mErr != nil {
			s.logger.ErrorWith("Failed to find mapping for forwarded-udp",
				slog.F("session_id", s.sessionID),
				slog.F("src_port", tcpIpMsg.SrcPort),
				slog.F("protocol", protocol))
			return
		}

		s.logger.DebugWith("Directly handling forwarded-udp channel",
			slog.F("session_id", s.sessionID),
			slog.F("src_port", tcpIpMsg.SrcPort),
			slog.F("protocol", protocol))

		// Dial the local destination (Server side)
		dstHost := mapping.TcpIpChannelMsg.DstHost
		dstPort := mapping.TcpIpChannelMsg.DstPort
		host := net.JoinHostPort(dstHost, strconv.Itoa(int(dstPort)))

		conn, cErr := net.Dial(protocol, host)
		if cErr != nil {
			s.logger.ErrorWith("Failed to connect to local destination",
				slog.F("session_id", s.sessionID),
				slog.F("host", host),
				slog.F("protocol", protocol),
				slog.F("err", cErr))
			return
		}
		defer func() { _ = conn.Close() }()

		s.logger.DebugWith("Bridged forwarded-udp channel",
			slog.F("session_id", s.sessionID),
			slog.F("target", host),
			slog.F("protocol", protocol))

		// Pipe the SSH channel to the local connection
		_, _ = sio.PipeWithCancel(channel, conn)
		return
	}
	s.logger.ErrorWith("SSH instance not found for forwarded-udp",
		slog.F("session_id", s.sessionID))
}

// SetSSHClient sets the SSH client connection (AgentRole/OperatorRole)
func (s *BidirectionalSession) SetSSHClient(client *ssh.Client) {
	s.sessionMutex.Lock()
	s.sshClient = client
	s.sessionMutex.Unlock()
}
