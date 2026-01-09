package session

import (
	"fmt"

	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// ========================================
// Client Mode Methods
// ========================================

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
// This is required by the remote.Session interface
func (s *BidirectionalSession) HandleForwardedTcpIpChannel(nc ssh.NewChannel) {
	s.logger.WarnWith("Received unexpected forwarded-tcpip channel",
		slog.F("session_id", s.sessionID),
		slog.F("role", s.role.String()),
		slog.F("channel_type", nc.ChannelType()))
	_ = nc.Reject(ssh.Prohibited, "forwarded-tcpip not supported in this session mode")
}

// SetSSHClient sets the SSH client connection (AgentRole/OperatorRole)
func (s *BidirectionalSession) SetSSHClient(client *ssh.Client) {
	s.sessionMutex.Lock()
	s.sshClient = client
	s.sessionMutex.Unlock()
}
