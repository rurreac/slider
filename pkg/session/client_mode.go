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

// HandleForwardedTcpIpChannel handles incoming forwarded-tcpip channels
// Called when a reverse port forward connection arrives
func (s *BidirectionalSession) HandleForwardedTcpIpChannel(nc ssh.NewChannel) {
	// Parse the channel data to get connection info
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
		slog.F("src_port", tcpIpMsg.SrcPort))

	// Accept the channel
	channel, requests, aErr := nc.Accept()
	if aErr != nil {
		s.logger.ErrorWith("Failed to accept forwarded-tcpip channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", aErr))
		return
	}
	defer func() { _ = channel.Close() }()
	go ssh.DiscardRequests(requests)

	// Dial the local destination
	host := net.JoinHostPort(tcpIpMsg.DstHost, strconv.Itoa(int(tcpIpMsg.DstPort)))
	conn, cErr := net.Dial("tcp", host)
	if cErr != nil {
		s.logger.ErrorWith("Failed to connect to local destination",
			slog.F("session_id", s.sessionID),
			slog.F("host", host),
			slog.F("err", cErr))
		return
	}
	defer func() { _ = conn.Close() }()

	// Pipe the SSH channel to the local connection
	_, _ = sio.PipeWithCancel(channel, conn)

	s.logger.DebugWith("Completed forwarded-tcpip channel",
		slog.F("session_id", s.sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort))
}

// SetSSHClient sets the SSH client connection (AgentRole/OperatorRole)
func (s *BidirectionalSession) SetSSHClient(client *ssh.Client) {
	s.sessionMutex.Lock()
	s.sshClient = client
	s.sessionMutex.Unlock()
}
