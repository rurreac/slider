package portforward

import (
	"encoding/json"
	"fmt"
	"io"
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
	remoteMappings map[string]*RemoteForward
	localMappings  map[string]*LocalForward
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
	Listener io.Closer
	*types.CustomTcpIpChannelMsg
}

// NewManager creates a new port forwarding manager
func NewManager(logger *slog.Logger, sessionID int64, conn ChannelOpener) *Manager {
	return &Manager{
		logger:         logger,
		sessionID:      sessionID,
		conn:           conn,
		remoteMappings: make(map[string]*RemoteForward),
		localMappings:  make(map[string]*LocalForward),
		forwardedTx:    &ForwardedTx{},
	}
}

// SetForwardedChannel sets the forwarded SSH channel for the manager
func (m *Manager) SetForwardedChannel(channel ssh.Channel) {
	m.forwardedTx.ForwardingMutex.Lock()
	m.forwardedTx.ForwardedSshChannel = channel
	m.forwardedTx.ForwardingMutex.Unlock()
}

func newProtocolPortKey(protocol string, port uint32) string {
	return fmt.Sprintf("%s:%d", protocol, port)
}

// AddRemoteForward adds a remote port forward mapping
func (m *Manager) AddRemoteForward(t *types.TcpIpChannelMsg, isSshConn bool, protocol string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := newProtocolPortKey(protocol, t.SrcPort)
	m.remoteMappings[key] = &RemoteForward{
		RcvChan:  make(chan *types.TcpIpChannelMsg, 5),
		DoneChan: make(chan bool, 5),
		CustomTcpIpChannelMsg: &types.CustomTcpIpChannelMsg{
			Protocol:        protocol,
			IsSshConn:       isSshConn,
			TcpIpChannelMsg: t,
		},
	}
}

// GetRemoteMappings returns all remote port forward mappings
func (m *Manager) GetRemoteMappings() map[string]*RemoteForward {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.remoteMappings
}

// GetRemoteMapping returns a specific remote port forward mapping
func (m *Manager) GetRemoteMapping(protocol string, port uint32) (*RemoteForward, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := newProtocolPortKey(protocol, port)
	mapping, ok := m.remoteMappings[key]
	if !ok {
		return nil, fmt.Errorf("no remote mapping found for %s port %d", protocol, port)
	}
	return mapping, nil
}

// AddLocalForward adds a local port forward mapping
func (m *Manager) AddLocalForward(t *types.TcpIpChannelMsg, listener io.Closer, isSshConn bool, protocol string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := newProtocolPortKey(protocol, t.SrcPort)
	m.localMappings[key] = &LocalForward{
		DoneChan: make(chan bool, 1),
		Listener: listener,
		CustomTcpIpChannelMsg: &types.CustomTcpIpChannelMsg{
			Protocol:        protocol,
			IsSshConn:       isSshConn,
			TcpIpChannelMsg: t,
		},
	}
}

// GetLocalMappings returns all local port forward mappings
func (m *Manager) GetLocalMappings() map[string]*LocalForward {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.localMappings
}

// GetLocalMapping returns a specific local port forward mapping
func (m *Manager) GetLocalMapping(protocol string, port uint32) (*LocalForward, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := newProtocolPortKey(protocol, port)
	mapping, ok := m.localMappings[key]
	if !ok {
		return nil, fmt.Errorf("no local mapping found for %s port %d", protocol, port)
	}
	return mapping, nil
}

// RemoveLocalForward removes a local port forward mapping
func (m *Manager) RemoveLocalForward(protocol string, port uint32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := newProtocolPortKey(protocol, port)
	delete(m.localMappings, key)
}

// RemoveRemoteForward removes a remote port forward mapping
func (m *Manager) RemoveRemoteForward(protocol string, port uint32) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	key := newProtocolPortKey(protocol, port)
	delete(m.remoteMappings, key)
}

// StartRemoteForward initiates a remote (reverse) port forward from a message
func (m *Manager) StartRemoteForward(msg types.CustomTcpIpChannelMsg, notifier chan error) {
	forwardReq := types.CustomTcpIpFwdRequest{
		Protocol:  msg.Protocol,
		IsSshConn: false,
		TcpIpFwdRequest: &types.TcpIpFwdRequest{
			BindAddress: msg.SrcHost,
			BindPort:    msg.SrcPort,
		},
		FwdHost: msg.DstHost, // Destination to forward connections to
		FwdPort: msg.DstPort, // Port to forward connections to
	}

	forwardReqBytes, mErr := json.Marshal(forwardReq)
	if mErr != nil {
		notifier <- fmt.Errorf("failed to marshal TcpIpFwdRequest request - %v", mErr)
		return
	}

	var ok bool
	var respData []byte
	var rErr error
	if msg.Protocol == conf.ForwardingProtocolUDP {
		ok, respData, rErr = m.conn.SendRequest(conf.SSHRequestSliderUDPForward, true, forwardReqBytes)
		if rErr != nil || !ok {
			if rErr == nil {
				rErr = fmt.Errorf("request was rejected, port likely in use")
			}
			notifier <- fmt.Errorf("failed to send \"%s\" request - %v", conf.SSHRequestSliderUDPForward, rErr)
			return
		}
	} else {
		ok, respData, rErr = m.conn.SendRequest(conf.SSHRequestTcpIpForward, true, forwardReqBytes)
		if rErr != nil || !ok {
			if rErr == nil {
				rErr = fmt.Errorf("request was rejected, port likely in use")
			}
			notifier <- fmt.Errorf("failed to send \"%s\" request - %v", conf.SSHRequestTcpIpForward, rErr)
			return
		}
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
	}, false, msg.Protocol)

	control, _ := m.GetRemoteMapping(msg.Protocol, msg.SrcPort)

	for range control.RcvChan {
		conn, cErr := net.Dial(msg.Protocol, net.JoinHostPort(msg.DstHost, strconv.Itoa(int(msg.DstPort))))
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
			m.logger.DebugWith("Completed MSG Forwarded channel",
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
	listener, lErr := net.Listen(conf.ForwardingProtocolTCP, fmt.Sprintf("%s:%d", msg.SrcHost, msg.SrcPort))
	if lErr != nil {
		notifier <- fmt.Errorf("failed to listen on %s %s:%d - %v", conf.ForwardingProtocolTCP, msg.SrcHost, msg.SrcPort, lErr)
		return
	}
	defer func() { _ = listener.Close() }()

	m.logger.DebugWith("Endpoint listening",
		slog.F("session_id", m.sessionID),
		slog.F("channel_type", conf.SSHChannelDirectTCPIP),
		slog.F("src_host", msg.SrcHost),
		slog.F("src_port", msg.SrcPort))

	m.AddLocalForward(&msg, listener, false, conf.ForwardingProtocolTCP)
	mapping, mErr := m.GetLocalMapping(conf.ForwardingProtocolTCP, msg.SrcPort)
	if mErr != nil {
		notifier <- fmt.Errorf("failed to get local port mapping - %v", mErr)
		return
	}

	for {
		select {
		case <-mapping.DoneChan:
			m.logger.DebugWith("Endpoint listener stopped",
				slog.F("session_id", m.sessionID),
				slog.F("channel_type", conf.SSHChannelDirectTCPIP),
				slog.F("src_host", msg.SrcHost),
				slog.F("src_port", msg.SrcPort))
			m.RemoveLocalForward(conf.ForwardingProtocolTCP, msg.SrcPort)
			return
		default:
			// Proceed
		}

		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(conf.EndpointTickerInterval))
		conn, cErr := listener.Accept()
		if cErr != nil {
			continue
		}

		oChan, oReq, oErr := m.conn.OpenChannel(conf.SSHChannelDirectTCPIP, ssh.Marshal(msg))
		if oErr != nil {
			m.logger.ErrorWith("Failed to open \"direct-tcpip\" channel",
				slog.F("session_id", m.sessionID),
				slog.F("channel_type", conf.SSHChannelDirectTCPIP),
				slog.F("err", oErr))
			_ = conn.Close()
			continue
		}
		go ssh.DiscardRequests(oReq)

		_, _ = sio.PipeWithCancel(conn, oChan)
	}
}

// StartLocalUDPForward initiates a local port forward from a message
func (m *Manager) StartLocalUDPForward(msg types.TcpIpChannelMsg, notifier chan error) {
	udpAddr, rErr := net.ResolveUDPAddr(conf.ForwardingProtocolUDP, fmt.Sprintf("%s:%d", msg.SrcHost, msg.SrcPort))
	if rErr != nil {
		notifier <- fmt.Errorf("failed to resolve UDP address %s:%d - %v", msg.SrcHost, msg.SrcPort, rErr)
		return
	}

	conn, lErr := net.ListenUDP(conf.ForwardingProtocolUDP, udpAddr)
	if lErr != nil {
		notifier <- fmt.Errorf("failed to listen on %s %s:%d - %v", conf.ForwardingProtocolUDP, msg.SrcHost, msg.SrcPort, lErr)
		return
	}
	defer func() { _ = conn.Close() }()

	m.logger.DebugWith("UDP Endpoint listening",
		slog.F("session_id", m.sessionID),
		slog.F("channel_type", conf.SSHChannelDirectUDP),
		slog.F("src_host", msg.SrcHost),
		slog.F("src_port", msg.SrcPort))

	// Listener wrapper for tracking
	// Create a dummy listener to satisfy AddLocalForward signature
	// Since UDP is connectionless, the "Listener" concept is slightly different,
	// but we store the connection to close it later via CloseAll/RemoveLocalForward
	m.AddLocalForward(&msg, conn, false, conf.ForwardingProtocolUDP)

	mapping, mErr := m.GetLocalMapping(conf.ForwardingProtocolUDP, msg.SrcPort)
	if mErr != nil {
		notifier <- fmt.Errorf("failed to get local port mapping - %v", mErr)
		return
	}

	// Map to track active "sessions" based on source address
	// Key: Source IP:Port (string), Value: SSH Channel
	sessions := make(map[string]ssh.Channel)
	sessionsMutex := sync.Mutex{}

	buffer := make([]byte, conf.MaxUDPPacketSize)

	for {
		select {
		case <-mapping.DoneChan:
			m.logger.DebugWith("Endpoint listener stopped",
				slog.F("session_id", m.sessionID),
				slog.F("channel_type", conf.SSHChannelDirectUDP),
				slog.F("src_host", msg.SrcHost),
				slog.F("src_port", msg.SrcPort))
			m.RemoveLocalForward(conf.ForwardingProtocolUDP, msg.SrcPort)

			// Cleanup all open channels
			sessionsMutex.Lock()
			for _, ch := range sessions {
				_ = ch.Close()
			}
			sessionsMutex.Unlock()
			return
		default:
			// Proceed
		}

		_ = conn.SetReadDeadline(time.Now().Add(conf.EndpointTickerInterval))
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			m.logger.ErrorWith("Failed to read from UDP connection",
				slog.F("session_id", m.sessionID),
				slog.F("err", err))
			continue
		}

		clientAddr := addr.String()
		sessionsMutex.Lock()
		sshCh, exists := sessions[clientAddr]
		sessionsMutex.Unlock()

		if !exists {
			// Open a new SSH channel for this client
			// Initialize new channel request
			reqPayload := ssh.Marshal(msg)
			newChannel, reqs, openErr := m.conn.OpenChannel(conf.SSHChannelDirectUDP, reqPayload)
			if openErr != nil {
				m.logger.ErrorWith("Failed to open \"direct-udp\" channel",
					slog.F("session_id", m.sessionID),
					slog.F("channel_type", conf.SSHChannelDirectUDP),
					slog.F("err", openErr))
				continue
			}
			go ssh.DiscardRequests(reqs)

			sshCh = newChannel
			sessionsMutex.Lock()
			sessions[clientAddr] = sshCh
			sessionsMutex.Unlock()

			// Handle responses from SSH channel -> UDP Client
			go func(ch ssh.Channel, targetAddr *net.UDPAddr) {
				defer func() {
					_ = ch.Close()
					sessionsMutex.Lock()
					delete(sessions, clientAddr)
					sessionsMutex.Unlock()
				}()

				// Read from SSH channel and write to UDP
				// Simplified pipe logic for UDP
				respBuf := make([]byte, 65535)
				for {
					rn, rErr := ch.Read(respBuf)
					if rErr != nil {
						return
					}
					if rn > 0 {
						_, wErr := conn.WriteToUDP(respBuf[:rn], targetAddr)
						if wErr != nil {
							return
						}
					}
				}
			}(sshCh, addr)
		}

		// Write payload to SSH channel
		_, wErr := sshCh.Write(buffer[:n])
		if wErr != nil {
			m.logger.ErrorWith("Failed to write to SSH channel",
				slog.F("session_id", m.sessionID),
				slog.F("err", wErr))
			// Close channel on write error (broken pipe)
			_ = sshCh.Close()
			sessionsMutex.Lock()
			delete(sessions, clientAddr)
			sessionsMutex.Unlock()
		}
	}
}

// CancelRemoteForward cancels a remote port forward
func (m *Manager) CancelRemoteForward(protocol string, port uint32) error {
	m.mutex.Lock()
	key := newProtocolPortKey(protocol, port)
	control, ok := m.remoteMappings[key]
	if !ok {
		m.mutex.Unlock()
		return fmt.Errorf("mapping not found: %s", key)
	}
	m.mutex.Unlock()

	if control.IsSshConn {
		return fmt.Errorf("refusing to terminate ssh port forwarding, kill ssh endpoint instead")
	}

	payload := ssh.Marshal(&types.TcpIpFwdRequest{
		BindAddress: control.SrcHost,
		BindPort:    control.SrcPort,
	})

	rOk, _, cErr := m.conn.SendRequest(conf.SSHRequestCancelTcpIpForward, true, payload)
	if cErr != nil || !rOk {
		return fmt.Errorf("failed to cancel reverse tcp forwarding - %v", cErr)
	}

	m.logger.DebugWith("Cancelled reverse tcp forwarding",
		slog.F("session_id", m.sessionID),
		slog.F("request_channel", conf.SSHRequestCancelTcpIpForward),
		slog.F("fwd_port", control.SrcPort))

	close(control.RcvChan)
	close(control.DoneChan)

	// Remove from map after successfully closing the port forward
	m.RemoveRemoteForward(protocol, port)

	return nil
}

// CancelAllSSHRemoteForwards cancels all SSH-initiated remote port forwards
func (m *Manager) CancelAllSSHRemoteForwards() {
	m.mutex.Lock()
	mappings := make(map[string]*RemoteForward)
	for k, v := range m.remoteMappings {
		if v.IsSshConn {
			mappings[k] = v
		}
	}
	m.mutex.Unlock()

	for _, portFwd := range mappings {
		payload := ssh.Marshal(&types.TcpIpFwdRequest{
			BindAddress: portFwd.SrcHost,
			BindPort:    portFwd.SrcPort,
		})

		ok, _, cErr := m.conn.SendRequest(conf.SSHRequestCancelTcpIpForward, true, payload)
		if cErr != nil || !ok {
			m.logger.ErrorWith("Failed to cancel reverse tcp forwarding",
				slog.F("session_id", m.sessionID),
				slog.F("request_channel", conf.SSHRequestCancelTcpIpForward),
				slog.F("fwd_host", portFwd.SrcHost),
				slog.F("fwd_port", portFwd.SrcPort),
				slog.F("err", cErr))
			continue
		}

		m.logger.DebugWith("Cancelled reverse tcp forwarding",
			slog.F("session_id", m.sessionID),
			slog.F("request_channel", conf.SSHRequestCancelTcpIpForward),
			slog.F("fwd_host", portFwd.SrcHost),
			slog.F("fwd_port", portFwd.SrcPort))

	}
}

// CloseAll closes all active port forwards (local and remote)
func (m *Manager) CloseAll() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Close Local Mappings (Listeners)
	for key, fwd := range m.localMappings {
		if fwd.Listener != nil {
			_ = fwd.Listener.Close()
		}
		// Signal done loop
		select {
		case fwd.DoneChan <- true:
		default:
		}
		delete(m.localMappings, key)
	}

	// Close Remote Mappings
	for key, fwd := range m.remoteMappings {
		// Signal done loop
		select {
		case fwd.DoneChan <- true:
		default:
		}
		close(fwd.RcvChan)
		delete(m.remoteMappings, key)
	}
}
