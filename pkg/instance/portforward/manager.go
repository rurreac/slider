package portforward

import (
	"encoding/json"
	"fmt"
	"net"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"
	"strconv"
	"sync"
	"time"

	"slider/pkg/conf"

	"golang.org/x/crypto/ssh"
)

// Manager handles port forwarding operations (both local and remote)
type Manager struct {
	logger         *slog.Logger
	sessionID      int64
	conn           ChannelOpener
	remoteMappings map[int]*RemoteForward
	localMappings  map[int]*LocalForward
	forwardedTx    *ForwardedTx
	mutex          sync.Mutex
}

// ChannelOpener defines the interface for opening SSH channels and sending requests
type ChannelOpener interface {
	OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

// ForwardedTx tracks forwarded SSH channels
type ForwardedTx struct {
	ForwardedSshChannel ssh.Channel
	ForwardingMutex     sync.Mutex
}

// RemoteForward represents a remote (reverse) port forward
type RemoteForward struct {
	RcvChan  chan *types.TcpIpChannelMsg
	DoneChan chan bool
	*types.CustomTcpIpChannelMsg
}

// LocalForward represents a local port forward
type LocalForward struct {
	RcvChan  chan *types.TcpIpChannelMsg
	DoneChan chan bool
	*types.CustomTcpIpChannelMsg
}

// NewManager creates a new port forwarding manager
func NewManager(logger *slog.Logger, sessionID int64, conn ChannelOpener) *Manager {
	return &Manager{
		logger:         logger,
		sessionID:      sessionID,
		conn:           conn,
		remoteMappings: make(map[int]*RemoteForward),
		localMappings:  make(map[int]*LocalForward),
		forwardedTx:    &ForwardedTx{},
	}
}

// SetForwardedChannel sets the forwarded SSH channel for the manager
func (m *Manager) SetForwardedChannel(channel ssh.Channel) {
	m.forwardedTx.ForwardingMutex.Lock()
	m.forwardedTx.ForwardedSshChannel = channel
	m.forwardedTx.ForwardingMutex.Unlock()
}

// AddRemoteForward adds a remote port forward mapping
func (m *Manager) AddRemoteForward(t *types.TcpIpChannelMsg, isSshConn bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.remoteMappings[int(t.SrcPort)] = &RemoteForward{
		RcvChan:  make(chan *types.TcpIpChannelMsg, 5),
		DoneChan: make(chan bool, 5),
		CustomTcpIpChannelMsg: &types.CustomTcpIpChannelMsg{
			IsSshConn:       isSshConn,
			TcpIpChannelMsg: t,
		},
	}
}

// GetRemoteMappings returns all remote port forward mappings
func (m *Manager) GetRemoteMappings() map[int]*RemoteForward {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.remoteMappings
}

// GetRemoteMapping returns a specific remote port forward mapping
func (m *Manager) GetRemoteMapping(port int) (*RemoteForward, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	mapping, ok := m.remoteMappings[port]
	if !ok {
		return nil, fmt.Errorf("no remote mapping found for port %d", port)
	}
	return mapping, nil
}

// AddLocalForward adds a local port forward mapping
func (m *Manager) AddLocalForward(t *types.TcpIpChannelMsg, isSshConn bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.localMappings[int(t.SrcPort)] = &LocalForward{
		DoneChan: make(chan bool, 1),
		CustomTcpIpChannelMsg: &types.CustomTcpIpChannelMsg{
			IsSshConn:       isSshConn,
			TcpIpChannelMsg: t,
		},
	}
}

// GetLocalMappings returns all local port forward mappings
func (m *Manager) GetLocalMappings() map[int]*LocalForward {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.localMappings
}

// GetLocalMapping returns a specific local port forward mapping
func (m *Manager) GetLocalMapping(port int) (*LocalForward, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	mapping, ok := m.localMappings[port]
	if !ok {
		return nil, fmt.Errorf("no local mapping found for port %d", port)
	}
	return mapping, nil
}

// RemoveLocalForward removes a local port forward mapping
func (m *Manager) RemoveLocalForward(port int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.localMappings, port)
}

// RemoveRemoteForward removes a remote port forward mapping
func (m *Manager) RemoveRemoteForward(port int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.remoteMappings, port)
}

// StartRemoteForward initiates a remote (reverse) port forward from a message
func (m *Manager) StartRemoteForward(msg types.CustomTcpIpChannelMsg, notifier chan error) {
	forwardReq := types.CustomTcpIpFwdRequest{
		IsSshConn: false,
		TcpIpFwdRequest: &types.TcpIpFwdRequest{
			BindAddress: msg.SrcHost,
			BindPort:    msg.SrcPort,
		},
	}

	forwardReqBytes, mErr := json.Marshal(forwardReq)
	if mErr != nil {
		notifier <- fmt.Errorf("failed to marshal TcpIpFwdRequest request - %v", mErr)
		return
	}

	ok, respData, rErr := m.conn.SendRequest("tcpip-forward", true, forwardReqBytes)
	if rErr != nil || !ok {
		if rErr == nil {
			rErr = fmt.Errorf("request was rejected, port likely in use")
		}
		notifier <- fmt.Errorf("failed to send \"tcpip-forward\" request - %v", rErr)
		return
	}

	if len(respData) > 0 {
		respPort := &types.TcpIpReqSuccess{}
		if uErr := ssh.Unmarshal(respData, respPort); uErr == nil {
			msg.SrcPort = respPort.BoundPort
		}
	}

	m.AddRemoteForward(&types.TcpIpChannelMsg{
		DstHost: msg.DstHost,
		DstPort: msg.DstPort,
		SrcHost: msg.SrcHost,
		SrcPort: msg.SrcPort,
	}, false)

	bindPort := int(msg.SrcPort)
	control, _ := m.GetRemoteMapping(bindPort)

	for range control.RcvChan {
		conn, cErr := net.Dial("tcp", net.JoinHostPort(msg.DstHost, strconv.Itoa(int(msg.DstPort))))
		if cErr != nil {
			m.logger.ErrorWith("Failed to connect to host",
				slog.F("session_id", m.sessionID),
				slog.F("dst_host", msg.DstHost),
				slog.F("dst_port", msg.DstPort),
				slog.F("err", cErr))
			control.DoneChan <- true
			continue
		}

		// Connect the two channels
		go func() {
			defer func() {
				_ = conn.Close()
			}()
			_, _ = sio.PipeWithCancel(conn, m.forwardedTx.ForwardedSshChannel)
			m.logger.DebugWith("Completed MSG TCPIP Forwarded channel",
				slog.F("session_id", m.sessionID),
				slog.F("src_host", msg.SrcHost),
				slog.F("src_port", msg.SrcPort),
				slog.F("dst_host", msg.DstHost),
				slog.F("dst_port", msg.DstPort))
			control.DoneChan <- true
		}()
	}
}

// StartLocalForward initiates a local port forward from a message
func (m *Manager) StartLocalForward(msg types.TcpIpChannelMsg, notifier chan error) {
	listener, lErr := net.Listen("tcp", fmt.Sprintf("%s:%d", msg.SrcHost, msg.SrcPort))
	if lErr != nil {
		notifier <- fmt.Errorf("failed to listen on %s:%d - %v", msg.SrcHost, msg.SrcPort, lErr)
		return
	}
	defer func() { _ = listener.Close() }()

	m.logger.DebugWith("Endpoint listening",
		slog.F("session_id", m.sessionID),
		slog.F("channel_type", "direct-tcpip"),
		slog.F("src_host", msg.SrcHost),
		slog.F("src_port", msg.SrcPort))

	m.AddLocalForward(&msg, false)
	mapping, mErr := m.GetLocalMapping(int(msg.SrcPort))
	if mErr != nil {
		notifier <- fmt.Errorf("failed to get local port mapping - %v", mErr)
		return
	}

	for {
		select {
		case <-mapping.DoneChan:
			m.logger.DebugWith("Endpoint listener stopped",
				slog.F("session_id", m.sessionID),
				slog.F("channel_type", "direct-tcpip"),
				slog.F("src_host", msg.SrcHost),
				slog.F("src_port", msg.SrcPort))
			m.RemoveLocalForward(int(msg.SrcPort))
			return
		default:
			// Proceed
		}

		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(conf.Timeout))
		conn, cErr := listener.Accept()
		if cErr != nil {
			continue
		}

		oChan, oReq, oErr := m.conn.OpenChannel("direct-tcpip", ssh.Marshal(msg))
		if oErr != nil {
			m.logger.ErrorWith("Failed to open \"direct-tcpip\" channel",
				slog.F("session_id", m.sessionID),
				slog.F("channel_type", "direct-tcpip"),
				slog.F("err", oErr))
			_ = conn.Close()
			continue
		}
		go ssh.DiscardRequests(oReq)

		_, _ = sio.PipeWithCancel(conn, oChan)
	}
}

// CancelRemoteForward cancels a remote port forward
func (m *Manager) CancelRemoteForward(port int) error {
	m.mutex.Lock()
	control, ok := m.remoteMappings[port]
	if !ok {
		m.mutex.Unlock()
		return fmt.Errorf("port %d not found", port)
	}
	m.mutex.Unlock()

	if control.IsSshConn {
		return fmt.Errorf("refusing to terminate ssh port forwarding, kill ssh endpoint instead")
	}

	payload := ssh.Marshal(&types.TcpIpFwdRequest{
		BindAddress: control.SrcHost,
		BindPort:    control.SrcPort,
	})

	rOk, _, cErr := m.conn.SendRequest("cancel-tcpip-forward", true, payload)
	if cErr != nil || !rOk {
		return fmt.Errorf("failed to cancel reverse tcp forwarding - %v", cErr)
	}

	m.logger.DebugWith("Cancelled reverse tcp forwarding",
		slog.F("session_id", m.sessionID),
		slog.F("request_channel", "cancel-tcpip-forward"),
		slog.F("fwd_port", control.SrcPort))

	close(control.RcvChan)
	close(control.DoneChan)

	// Remove from map after successfully closing the port forward
	m.RemoveRemoteForward(port)

	return nil
}

// CancelAllSSHRemoteForwards cancels all SSH-initiated remote port forwards
func (m *Manager) CancelAllSSHRemoteForwards() {
	m.mutex.Lock()
	mappings := make(map[int]*RemoteForward)
	for k, v := range m.remoteMappings {
		if v.IsSshConn {
			mappings[k] = v
		}
	}
	m.mutex.Unlock()

	for port, portFwd := range mappings {
		payload := ssh.Marshal(&types.TcpIpFwdRequest{
			BindAddress: portFwd.SrcHost,
			BindPort:    portFwd.SrcPort,
		})

		ok, _, cErr := m.conn.SendRequest("cancel-tcpip-forward", true, payload)
		if cErr != nil || !ok {
			m.logger.ErrorWith("Failed to cancel reverse tcp forwarding",
				slog.F("session_id", m.sessionID),
				slog.F("request_channel", "cancel-tcpip-forward"),
				slog.F("fwd_host", portFwd.SrcHost),
				slog.F("fwd_port", portFwd.SrcPort),
				slog.F("err", cErr))
			continue
		}

		m.logger.DebugWith("Cancelled reverse tcp forwarding",
			slog.F("session_id", m.sessionID),
			slog.F("request_channel", "cancel-tcpip-forward"),
			slog.F("fwd_host", portFwd.SrcHost),
			slog.F("fwd_port", portFwd.SrcPort))

		m.RemoveRemoteForward(port)
	}
}
