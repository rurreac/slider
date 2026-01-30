package portforward

import (
	"encoding/json"
	"slider/pkg/conf"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// SSHServerConn represents the minimal SSH server connection interface needed
type SSHServerConn interface {
	OpenChannel(name string, data []byte) (ssh.Channel, <-chan *ssh.Request, error)
}

// HandleTcpIpForwardRequest handles incoming tcpip-forward SSH requests
// This is called when an SSH client requests a remote port forward
func (m *Manager) HandleTcpIpForwardRequest(req *ssh.Request, sshServerConn SSHServerConn) {
	// Parse the incoming request
	srcReqPayload := &types.TcpIpFwdRequest{}
	if uErr := ssh.Unmarshal(req.Payload, srcReqPayload); uErr != nil {
		m.logger.ErrorWith("Failed to unmarshal TcpIpFwdRequest request",
			slog.F("session_id", m.sessionID),
			slog.F("request_type", conf.SSHRequestTcpIpForward),
			slog.F("err", uErr))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// Forward the request to the Slider client
	customReqPayload := &types.CustomTcpIpFwdRequest{
		IsSshConn:       true,
		TcpIpFwdRequest: srcReqPayload,
	}

	reqPayload, mErr := json.Marshal(customReqPayload)
	if mErr != nil {
		m.logger.ErrorWith("Failed to marshal request",
			slog.F("session_id", m.sessionID),
			slog.F("request_type", conf.SSHRequestTcpIpForward),
			slog.F("err", mErr))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	rOk, sliderRespData, rErr := m.conn.SendRequest(conf.SSHRequestTcpIpForward, req.WantReply, reqPayload)
	if rErr != nil || !rOk {
		m.logger.ErrorWith("Failed to send slider client request",
			slog.F("session_id", m.sessionID),
			slog.F("request_type", conf.SSHRequestTcpIpForward),
			slog.F("err", rErr))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	sshRespPayload := &types.TcpIpReqSuccess{}
	if req.WantReply {
		// Handle port 0 binding (dynamic port allocation)
		if sliderRespData == nil && srcReqPayload.BindPort == 0 {
			m.logger.ErrorWith("Failed to bind to port",
				slog.F("session_id", m.sessionID),
				slog.F("request_type", conf.SSHRequestTcpIpForward),
				slog.F("bind_port", srcReqPayload.BindPort))
			_ = req.Reply(false, nil)
			return
		}

		respPayload := make([]byte, 0)
		if srcReqPayload.BindPort == 0 {
			if uErr := ssh.Unmarshal(sliderRespData, sshRespPayload); uErr != nil {
				m.logger.ErrorWith("Failed to unmarshal request",
					slog.F("session_id", m.sessionID),
					slog.F("request_type", conf.SSHRequestTcpIpForward),
					slog.F("err", uErr))
				_ = req.Reply(false, nil)
				return
			}

			respPayload = ssh.Marshal(sshRespPayload)
			srcReqPayload.BindPort = sshRespPayload.BoundPort
		}

		if wErr := req.Reply(true, respPayload); wErr != nil {
			m.logger.ErrorWith("Failed to reply to original request",
				slog.F("session_id", m.sessionID),
				slog.F("request_type", conf.SSHRequestTcpIpForward),
				slog.F("err", wErr))
			return
		}

		// Add the remote mapping
		m.AddRemoteForward(&types.TcpIpChannelMsg{
			// Destination is handled by SSH client
			DstHost: "",
			DstPort: 0,
			SrcHost: srcReqPayload.BindAddress,
			SrcPort: srcReqPayload.BindPort,
		}, true)
	}

	control, _ := m.GetRemoteMapping(int(srcReqPayload.BindPort))

	// Handle incoming connections on the forwarded port
	for channelMsg := range control.RcvChan {
		channel, tcpIpFwdReq, oErr := sshServerConn.OpenChannel(conf.SSHChannelForwardedTCPIP, ssh.Marshal(channelMsg))
		if oErr != nil {
			m.logger.ErrorWith("Failed to open channel to client",
				slog.F("session_id", m.sessionID),
				slog.F("request_channel", conf.SSHChannelForwardedTCPIP),
				slog.F("err", oErr))
			control.DoneChan <- true
			continue
		}
		go ssh.DiscardRequests(tcpIpFwdReq)

		// Pipe the channels together
		go func() {
			defer func() {
				_ = channel.Close()
			}()
			_, _ = sio.PipeWithCancel(channel, m.forwardedTx.ForwardedSshChannel)
			control.DoneChan <- true
			m.logger.DebugWith("Completed SSH Port Forward channel from remote",
				slog.F("session_id", m.sessionID),
				slog.F("request_channel", conf.SSHChannelForwardedTCPIP),
				slog.F("src_host", srcReqPayload.BindAddress),
				slog.F("src_port", srcReqPayload.BindPort))
		}()
	}
}

// HandleDirectTcpIpChannel handles incoming direct-tcpip channel requests
// This is called when an SSH client opens a local port forward channel
func (m *Manager) HandleDirectTcpIpChannel(nc ssh.NewChannel) error {
	sessionClientChannel, request, aErr := nc.Accept()
	if aErr != nil {
		return aErr
	}
	defer func() { _ = sessionClientChannel.Close() }()
	go ssh.DiscardRequests(request)

	var dti types.TcpIpChannelMsg
	if uErr := ssh.Unmarshal(nc.ExtraData(), &dti); uErr != nil {
		return uErr
	}

	m.logger.DebugWith("Direct TCPIP channel request",
		slog.F("session_id", m.sessionID),
		slog.F("request_channel", conf.SSHChannelDirectTCPIP),
		slog.F("dst_host", dti.DstHost),
		slog.F("dst_port", dti.DstPort),
		slog.F("src_host", dti.SrcHost),
		slog.F("src_port", dti.SrcPort))

	// Store the channel for forwarding
	m.forwardedTx.ForwardingMutex.Lock()
	m.forwardedTx.ForwardedSshChannel = sessionClientChannel
	m.forwardedTx.ForwardingMutex.Unlock()

	// Get the control channel for this mapping
	control, cErr := m.GetRemoteMapping(int(dti.DstPort))
	if cErr != nil {
		return cErr
	}

	// Send the connection info to the forwarding goroutine
	control.RcvChan <- &dti

	// Wait for completion
	<-control.DoneChan

	return nil
}
