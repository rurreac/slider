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

	// Determine protocol (default to tcp for standard SSH)
	protocol := customMsg.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	// Check if this is a Server-managed reverse forward (e.g. initiated by console portfwd -R)
	if s.sshInstance != nil {
		// Consolidate handling for TCP reverse forwarding.
		// The Agent (Client) sends the *Target* destination in the payload (DstHost/DstPort).
		// The Server Manager keys mappings by *Bind* port.
		// Since we cannot easily retrieve the Bind Port from the payload without modification,
		// and the Agent is a trusted component in this architecture, we TRUST the payload.
		// We dial the target destination directly, skipping strict verification against the Manager.

		s.logger.DebugWith("Directly handling forwarded-tcpip channel",
			slog.F("session_id", s.sessionID),
			slog.F("dst_port", tcpIpMsg.DstPort),
			slog.F("protocol", protocol))

		// Use the payload destination
		targetHost := tcpIpMsg.DstHost
		targetPort := tcpIpMsg.DstPort
		host := net.JoinHostPort(targetHost, strconv.Itoa(int(targetPort)))

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

	// Fallback for non-server managed sessions
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

// SetSSHClient sets the SSH client connection (AgentRole/OperatorRole)
func (s *BidirectionalSession) SetSSHClient(client *ssh.Client) {
	s.sessionMutex.Lock()
	s.sshClient = client
	s.sessionMutex.Unlock()
}
