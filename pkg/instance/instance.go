package instance

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"io"
	"net"
	"os"
	"os/signal"
	"slider/pkg/conf"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync"
	"syscall"
	"time"
)

const (
	sshClientScope     = "ssh-client"
	sshSessionScope    = "ssh-session"
	sliderChannelScope = "slider-channel"
	SocksEndpoint      = "socks-endpoint"
	ShellEndpoint      = "shell-endpoint"
	SshEndpoint        = "ssh-endpoint"
)

type Config struct {
	Logger               *slog.Logger
	LogPrefix            string
	port                 int
	ServerKey            ssh.Signer
	AuthOn               bool
	allowedFingerprint   string
	exposePort           bool
	ptyOn                bool
	enabled              bool
	stopSignal           chan bool
	done                 chan bool
	instanceMutex        sync.Mutex
	sshServerConn        *ssh.ServerConn
	sshSessionConn       ssh.Conn
	sshClientChannel     <-chan ssh.NewChannel
	EndpointType         string
	tlsOn                bool
	interactiveOn        bool
	CertificateAuthority *scrypt.CertificateAuthority
	certExists           bool
	serverCertificate    *scrypt.GeneratedCertificate
	envVarList           []struct{ Key, Value string }
	portFwdMap           map[int]PortForwardControl
	directTcpIpMap       map[int]DirectTcpIpControl
	FTx                  ForwardedTx
}

type ForwardedTx struct {
	ForwardedSshChannel ssh.Channel
	ForwardingMutex     sync.Mutex
}

type PortForwardControl struct {
	RcvChan  chan *types.TcpIpChannelMsg
	DoneChan chan bool
	*types.CustomTcpIpChannelMsg
}

type DirectTcpIpControl struct {
	RcvChan   chan *types.TcpIpChannelMsg
	DoneChan  chan bool
	isForward bool
	*types.CustomTcpIpChannelMsg
}

func New(config *Config) *Config {
	c := config
	c.envVarList = make([]struct{ Key, Value string }, 0)
	return c
}

func (si *Config) SetExpose(expose bool) {
	si.instanceMutex.Lock()
	si.exposePort = expose
	si.instanceMutex.Unlock()
}

func (si *Config) SetPtyOn(ptyOn bool) {
	si.instanceMutex.Lock()
	si.ptyOn = ptyOn
	si.instanceMutex.Unlock()
}

func (si *Config) setControls() {
	si.instanceMutex.Lock()
	si.stopSignal = make(chan bool, 1)
	si.done = make(chan bool, 1)
	si.instanceMutex.Unlock()
}

func (si *Config) SetSSHConn(conn ssh.Conn) {
	si.instanceMutex.Lock()
	si.sshSessionConn = conn
	si.instanceMutex.Unlock()
}

func (si *Config) setPort(port int) {
	si.instanceMutex.Lock()
	si.port = port
	si.enabled = true
	si.instanceMutex.Unlock()
}

func (si *Config) setServerCertificate(cert *scrypt.GeneratedCertificate) {
	si.instanceMutex.Lock()
	si.certExists = true
	si.serverCertificate = cert
	si.instanceMutex.Unlock()
}

func (si *Config) SetTLSOn(tlsOn bool) {
	si.instanceMutex.Lock()
	si.tlsOn = tlsOn
	si.instanceMutex.Unlock()
}

func (si *Config) SetInteractiveOn(interactiveOn bool) {
	si.instanceMutex.Lock()
	si.interactiveOn = interactiveOn
	si.instanceMutex.Unlock()
}

func (si *Config) SetAllowedFingerprint(fp string) {
	si.instanceMutex.Lock()
	si.allowedFingerprint = fp
	si.instanceMutex.Unlock()
}

func (si *Config) SetEnvVarList(evl []struct{ Key, Value string }) {
	si.instanceMutex.Lock()
	si.envVarList = evl
	si.instanceMutex.Unlock()
}

func (si *Config) StartEndpoint(port int) error {
	// net.Listen does not error when something is listening on a port on 0.0.0.0,
	// and we attempt to listen on 127.0.0.1 on the same port.
	// To overcome this issue we will try 0.0.0.0 first.
	var listener net.Listener
	var lErr error
	listener, lErr = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if lErr != nil {
		return fmt.Errorf("can not listen for connections - %v", lErr)
	}
	if !si.isExposed() {
		_ = listener.Close()
		listener, lErr = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if lErr != nil {
			return fmt.Errorf("can not listen for localhost connections - %v", lErr)
		}
	}
	si.setControls()
	port = listener.Addr().(*net.TCPAddr).Port
	si.setPort(port)

	go func() {
		if <-si.stopSignal; true {
			close(si.stopSignal)
			_ = listener.Close()
		}
	}()

	si.Logger.Debugf(si.LogPrefix+"Triggering Listener on Port %d", port)
	for {
		conn, aErr := listener.Accept()
		if aErr != nil {
			break
		}
		switch si.EndpointType {
		case SocksEndpoint:
			go si.runSocksComm(conn)
		case ShellEndpoint:
			go si.runShellComm(conn)
		case SshEndpoint:
			go si.runSshComm(conn)
		default:
			return fmt.Errorf(si.LogPrefix+"Unknown endpoint type \"%s\"", si.EndpointType)
		}
	}

	si.done <- true
	return nil
}

func (si *Config) runSshComm(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	sshConf := &ssh.ServerConfig{NoClientAuth: true}
	if si.AuthOn {
		sshConf.NoClientAuth = false
		sshConf.PublicKeyCallback = si.clientVerification
	}
	sshConf.AddHostKey(si.ServerKey)

	var reqChan <-chan *ssh.Request
	var cErr error
	si.sshServerConn, si.sshClientChannel, reqChan, cErr = ssh.NewServerConn(conn, sshConf)
	if cErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed SSH handshake - %v", cErr)
		return
	}
	defer func() {
		_ = si.sshServerConn.Close()
		si.cancelSshRemoteFwd()
	}()

	// Service incoming SSH Request channel
	go si.handleRequests(nil, reqChan, sshClientScope)

	for nc := range si.sshClientChannel {
		switch nc.ChannelType() {
		case "session":
			sessionClientChannel, request, aErr := nc.Accept()
			if aErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Could not accept channel - %v", aErr)
			}
			go si.handleRequests(sessionClientChannel, request, sshSessionScope)
		case "direct-tcpip":
			go func() {
				if hErr := si.handleDirectTcpIpChannel(nc); hErr != nil {
					si.Logger.Errorf(si.LogPrefix+"%v", hErr)
				}
			}()
		default:
			si.Logger.Warnf(si.LogPrefix+"SSH Rejected channel type \"%s\", payload: %v", nc.ChannelType(), nc.ExtraData())
			_ = nc.Reject(ssh.UnknownChannelType, "")
		}
	}
}

func (si *Config) runSocksComm(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	socksChan, reqs, oErr := si.sshSessionConn.OpenChannel("socks5", nil)
	if oErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to open \"socks5\" channel - %v", oErr)
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(reqs)

	_, _ = sio.PipeWithCancel(socksChan, conn)
}

func (si *Config) runShellComm(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	width, height, tErr := term.GetSize(int(os.Stdout.Fd()))
	if tErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to get terminal size - %v", tErr)
		return
	}

	initSize, uErr := json.Marshal(
		&types.TermDimensions{
			Width:  uint32(width),
			Height: uint32(height),
		},
	)
	if uErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to marshal init terminal size - %v", uErr)
		return
	}

	// Send message with initial size
	initChan, reqs, oErr := si.sshSessionConn.OpenChannel("init-size", initSize)
	if oErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to open \"socks5\" channel - %v", oErr)
		return
	}
	go ssh.DiscardRequests(reqs)
	_ = initChan.Close()

	winChange := make(chan []byte, 10)
	defer close(winChange)
	envChange := make(chan []byte, 10)
	defer close(envChange)

	si.interactiveConnPipe(conn, "shell", nil, winChange, envChange)
}

func (si *Config) handleRequests(sessionClientChannel ssh.Channel, requests <-chan *ssh.Request, scope string) {
	winChange := make(chan []byte, 10)
	defer close(winChange)
	envChange := make(chan []byte, 10)
	defer close(envChange)

	var envCloser struct{ Key, Value string }
	envCloser.Key = "SLIDER_ENV"
	envCloser.Value = "true"
	envCloserBytes := ssh.Marshal(envCloser)

	for req := range requests {
		ok := false
		if req.Type != "env" {
			si.Logger.Debugf(si.LogPrefix+"Scope \"%s\" - Request Type \"%s\" - payload: %v", scope, req.Type, req.Payload)
		}
		switch req.Type {
		case "shell":
			ok = true
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			// At this point all environment variables are already set
			envChange <- envCloserBytes
			go si.interactiveChannelPipe(sessionClientChannel, req.Type, nil, winChange, envChange)
		case "exec":
			ok = true
			if req.WantReply {
				go func() {
					_ = req.Reply(ok, nil)
				}()
			}
			// At this point all environment variables are already set
			envChange <- envCloserBytes
			go si.interactiveChannelPipe(sessionClientChannel, req.Type, req.Payload, winChange, envChange)
		case "pty-req":
			// Answering pty-req request true if Slider client has ptyOn
			if si.ptyOn {
				ok = true
				// Process req-pty info to Slider client through a new channel "init-size"
				si.sendInitTermSize(req.Payload)
			}
			if req.WantReply {
				go func() {
					_ = req.Reply(ok, nil)
				}()
			}
		case "window-change":
			if si.ptyOn {
				ok = true
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			winChange <- req.Payload
		case "env":
			ok = true
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			envChange <- req.Payload
		case "subsystem":
			if string(req.Payload[4:]) == "sftp" {
				ok = true
				go si.channelPipe(sessionClientChannel, "sftp", nil)
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		case "tcpip-forward":
			go si.handleTcpIpForwardRequest(req)
		default:
			si.Logger.Debugf(si.LogPrefix+"Request status: %v - type: %s - payload: %s", ok, req.Type, req.Payload)
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		}
	}
}

func (si *Config) TcpIpForwardFromMsg(msg types.CustomTcpIpChannelMsg) {
	forwardReq := types.CustomTcpIpFwdRequest{
		IsSshConn: false,
		TcpIpFwdRequest: &types.TcpIpFwdRequest{
			BindAddress: msg.SrcHost,
			BindPort:    msg.SrcPort,
		},
	}

	forwardReqBytes, mErr := json.Marshal(forwardReq)
	if mErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to marshal TcpIpFwdRequest request - %v", mErr)
		return
	}

	ok, respData, rErr := si.sshSessionConn.SendRequest("tcpip-forward", true, forwardReqBytes)
	if rErr != nil || !ok {
		si.Logger.Errorf(si.LogPrefix+"Failed to send \"tcpip-forward\" request - %v", rErr)
		return
	}
	if len(respData) > 0 {
		respPort := &types.TcpIpReqSuccess{}
		if uErr := ssh.Unmarshal(respData, respPort); uErr != nil {
			msg.SrcPort = respPort.BoundPort
		}
	}

	si.addRemoteMapping(&types.TcpIpChannelMsg{
		DstHost: msg.DstHost,
		DstPort: msg.DstPort,
		SrcHost: msg.SrcHost,
		SrcPort: msg.SrcPort,
	}, false)

	bindPort := int(msg.SrcPort)
	control := si.portFwdMap[bindPort]

	for range control.RcvChan {
		conn, cErr := net.Dial("tcp", fmt.Sprintf("%s:%d", msg.DstHost, msg.DstPort))
		if cErr != nil {
			si.Logger.Errorf(si.LogPrefix+"Failed to connect to %s:%d - %v", msg.DstHost, msg.DstPort, cErr)
			si.portFwdMap[bindPort].DoneChan <- true
			continue
		}

		// Connect the two channels
		go func() {
			defer func() {
				_ = conn.Close()
			}()
			_, _ = sio.PipeWithCancel(conn, si.FTx.ForwardedSshChannel)
			si.Logger.Debugf(si.LogPrefix+"Completed MSG TCPIP Forwarded channel %s:%d -> %s:%d",
				msg.SrcHost, msg.SrcPort,
				msg.DstHost, msg.DstPort,
			)
			control.DoneChan <- true
		}()
	}
}

func (si *Config) addLocalMapping(t *types.TcpIpChannelMsg, isSshConn bool) {
	si.instanceMutex.Lock()
	if si.directTcpIpMap == nil {
		si.directTcpIpMap = make(map[int]DirectTcpIpControl)
	}
	si.directTcpIpMap[int(t.SrcPort)] = DirectTcpIpControl{
		DoneChan: make(chan bool, 1),
		CustomTcpIpChannelMsg: &types.CustomTcpIpChannelMsg{
			IsSshConn:       isSshConn,
			TcpIpChannelMsg: t,
		},
	}
	si.instanceMutex.Unlock()
}

func (si *Config) GetLocalMappings() map[int]DirectTcpIpControl {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	return si.directTcpIpMap
}

func (si *Config) GetLocalPortMapping(port int) (DirectTcpIpControl, error) {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	mapping, ok := si.directTcpIpMap[port]
	if !ok {
		return DirectTcpIpControl{}, fmt.Errorf("no mapping found for port %d", port)
	}
	return mapping, nil
}

func (si *Config) DirectTcpIpFromMsg(msg types.TcpIpChannelMsg) {
	listener, lErr := net.Listen("tcp", fmt.Sprintf("%s:%d", msg.SrcHost, msg.SrcPort))
	if lErr != nil {
		si.Logger.Errorf("failed to listen on %s:%d - %v", msg.SrcHost, msg.SrcPort, lErr)
		return
	}
	defer func() { _ = listener.Close() }()
	si.Logger.Debugf(si.LogPrefix+"Listening on %s:%d", msg.SrcHost, msg.SrcPort)

	si.addLocalMapping(&msg, false)
	mapping, mErr := si.GetLocalPortMapping(int(msg.SrcPort))
	if mErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to get local port mapping - %v", mErr)
		return
	}

	for {
		select {
		case <-mapping.DoneChan:
			si.Logger.Debugf(si.LogPrefix+"Stopping listener on %s:%d", msg.SrcHost, msg.SrcPort)
			delete(si.directTcpIpMap, int(msg.SrcPort))
			return
		default:
			// Proceed
		}

		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(conf.Timeout))
		conn, cErr := listener.Accept()
		if cErr != nil {
			continue
		}

		oChan, oReq, oErr := si.sshSessionConn.OpenChannel("direct-tcpip", ssh.Marshal(msg))
		if oErr != nil {
			si.Logger.Errorf(si.LogPrefix+"Failed to open \"direct-tcpip\" channel - %v", oErr)
			_ = conn.Close()
			continue
		}
		go ssh.DiscardRequests(oReq)

		_, _ = sio.PipeWithCancel(conn, oChan)
	}

}

func (si *Config) handleTcpIpForwardRequest(req *ssh.Request) {
	// Just making sure that data received is what it should be
	srcReqPayload := &types.TcpIpFwdRequest{}
	if uErr := ssh.Unmarshal(req.Payload, srcReqPayload); uErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to unmarshal TcpIpFwdRequest request - %v", uErr)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// Send the request to the Slider client as it is
	customReqPayload := &types.CustomTcpIpFwdRequest{
		IsSshConn:       true,
		TcpIpFwdRequest: srcReqPayload,
	}
	reqPayload, mErr := json.Marshal(customReqPayload)
	if mErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to marshal TcpIpFwdRequest request - %v", mErr)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	rOk, sliderRespData, rErr := si.sshSessionConn.SendRequest("tcpip-forward", req.WantReply, reqPayload)
	if rErr != nil || !rOk {
		si.Logger.Errorf(si.LogPrefix+"Failed to send slider \"tcpip-forward\" request - %v", rErr)
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	sshRespPayload := &types.TcpIpReqSuccess{}
	if req.WantReply {
		// If the request was to bind to port 0, there should be data in the Slider response
		if sliderRespData == nil && srcReqPayload.BindPort == 0 {
			si.Logger.Errorf(si.LogPrefix+"Failed to bind to port %d", srcReqPayload.BindPort)
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
			return
		}

		// If the request was to bind to port != 0, no data response is expected
		respPayload := make([]byte, 0)
		// If the request was to bind to port 0, we need to respond with the bound port
		if srcReqPayload.BindPort == 0 {
			if uErr := ssh.Unmarshal(sliderRespData, sshRespPayload); uErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Failed to unmarshal TcpIpReqSuccess request - %v", uErr)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
				return
			}

			// Override the 0 port with the bound port for tracking
			respPayload = ssh.Marshal(sshRespPayload)
			srcReqPayload.BindPort = sshRespPayload.BoundPort
		}

		if wErr := req.Reply(true, respPayload); wErr != nil {
			si.Logger.Errorf(si.LogPrefix+"Failed to reply to original \"tcpip-forward\" request - %v", wErr)
			return
		}

		si.addRemoteMapping(&types.TcpIpChannelMsg{
			// Destination here corresponds to the SSH channel,
			// the SSH client handles the forwarding to the actual destination
			DstHost: "",
			DstPort: 0,
			SrcHost: srcReqPayload.BindAddress,
			SrcPort: srcReqPayload.BindPort,
		}, true)
	}

	control := si.portFwdMap[int(srcReqPayload.BindPort)]

	for channelMsg := range control.RcvChan {

		channel, tcpIpFwdReq, oErr := si.sshServerConn.OpenChannel("forwarded-tcpip", ssh.Marshal(channelMsg))
		if oErr != nil {
			si.Logger.Errorf(si.LogPrefix+"Failed to open \"forwarded-tcpip\" channel to client - %v", oErr)
			control.DoneChan <- true
			continue
		}
		go ssh.DiscardRequests(tcpIpFwdReq)

		// Connect the two channels
		go func() {
			defer func() {
				_ = channel.Close()
			}()
			_, _ = sio.PipeWithCancel(channel, si.FTx.ForwardedSshChannel)
			control.DoneChan <- true
			si.Logger.Debugf(si.LogPrefix+"Completed SSH Port Forward channel from remote %s:%d",
				srcReqPayload.BindAddress, srcReqPayload.BindPort,
			)
		}()
	}
}

func (si *Config) addRemoteMapping(t *types.TcpIpChannelMsg, isSshConn bool) {
	si.instanceMutex.Lock()
	if si.portFwdMap == nil {
		si.portFwdMap = make(map[int]PortForwardControl)
	}
	si.portFwdMap[int(t.SrcPort)] = PortForwardControl{
		RcvChan:  make(chan *types.TcpIpChannelMsg, 5),
		DoneChan: make(chan bool, 5),
		CustomTcpIpChannelMsg: &types.CustomTcpIpChannelMsg{
			IsSshConn:       isSshConn,
			TcpIpChannelMsg: t,
		},
	}
	si.instanceMutex.Unlock()
}

func (si *Config) GetRemoteMappings() map[int]PortForwardControl {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	return si.portFwdMap
}

func (si *Config) GetRemotePortMapping(port int) (PortForwardControl, error) {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	mapping, ok := si.portFwdMap[port]
	if !ok {
		return PortForwardControl{}, fmt.Errorf("no mapping found for port %d", port)
	}
	return mapping, nil
}

func (si *Config) cancelSshRemoteFwd() {
	if len(si.portFwdMap) > 0 {
		for _, portFwd := range si.portFwdMap {
			if portFwd.IsSshConn {

				payload := ssh.Marshal(&types.TcpIpFwdRequest{
					BindAddress: portFwd.SrcHost,
					BindPort:    portFwd.SrcPort,
				})
				ok, _, cErr := si.sshSessionConn.SendRequest("cancel-tcpip-forward", true, payload)
				if cErr != nil || !ok {
					si.Logger.Errorf(si.LogPrefix+"Failed to cancel reverse tcp forwarding - %v - %v", cErr, ok)
					continue
				}
				si.Logger.Debugf(si.LogPrefix+"Cancelled reverse tcp forwarding for port %d", portFwd.SrcPort)
				delete(si.portFwdMap, int(portFwd.SrcPort))
			}
		}
	}
}

func (si *Config) CancelMsgRemoteFwd(port int) error {
	si.instanceMutex.Lock()
	control, ok := si.portFwdMap[port]
	if !ok {
		si.instanceMutex.Unlock()
		return fmt.Errorf("port %d not found", port)
	}
	si.instanceMutex.Unlock()

	if control.IsSshConn {
		return fmt.Errorf("refusing to terminate ssh port forwarding, kill ssh endpoint instead")
	}

	payload := ssh.Marshal(&types.TcpIpFwdRequest{
		BindAddress: control.SrcHost,
		BindPort:    control.SrcPort,
	})
	rOk, _, cErr := si.sshSessionConn.SendRequest("cancel-tcpip-forward", true, payload)
	if cErr != nil || !rOk {
		return fmt.Errorf("failed to cancel reverse tcp forwarding - %v", cErr)
	}

	si.Logger.Debugf(si.LogPrefix+"Cancelled reverse tcp forwarding for port %d", control.SrcPort)
	close(control.RcvChan)
	close(control.DoneChan)

	// Remove from map after successfully closing the port forward
	si.instanceMutex.Lock()
	delete(si.portFwdMap, port)
	si.instanceMutex.Unlock()

	return nil
}

func (si *Config) handleDirectTcpIpChannel(nc ssh.NewChannel) error {
	sessionClientChannel, request, aErr := nc.Accept()
	if aErr != nil {
		return fmt.Errorf("could not accept channel - %v", aErr)
	}
	defer func() { _ = sessionClientChannel.Close() }()
	go ssh.DiscardRequests(request)

	var dti types.TcpIpChannelMsg
	if uErr := ssh.Unmarshal(nc.ExtraData(), &dti); uErr != nil {
		return fmt.Errorf("could not parse direct TCPIP - %v", uErr)
	}
	si.Logger.Debugf(si.LogPrefix+"request to %s:%d from %s:%d", dti.DstHost, dti.DstPort, dti.SrcHost, dti.SrcPort)

	// Create a connection to target via a socks5 channel
	// We'll handle direct-tcpip by opening a socks5 channel to the client
	socksChannel, socksRequests, oErr := si.sshSessionConn.OpenChannel("socks5", nil)
	if oErr != nil {
		return fmt.Errorf("could not open socks5 channel - %v", oErr)
	}
	defer func() { _ = socksChannel.Close() }()

	// Discard the SSH requests from the socks channel
	go ssh.DiscardRequests(socksRequests)

	// Because SOCKS comes from SSH, we need to perform the negotiation handshake first
	// https://datatracker.ietf.org/doc/html/rfc1928#section-3
	socks := socksConfig{
		sessionClientChannel: sessionClientChannel,
		socksChannel:         socksChannel,
		directTCPIP:          dti,
	}

	if ok, hErr := socks.handshake(); !ok || hErr != nil {
		return hErr
	}
	// Now we can start piping data between the channels
	si.Logger.Debugf(si.LogPrefix+"connection established to %s:%d", dti.DstHost, dti.DstPort)

	_, _ = sio.PipeWithCancel(sessionClientChannel, socksChannel)

	return nil
}

// sendInitTermSize receives a req-pty payload extracts the terminal size and sends it through an init-size channel payload
func (si *Config) sendInitTermSize(payload []byte) {
	// Do not panic if payload happens to be empty
	if len(payload) > 0 {
		var ptyReq types.PtyRequest
		if uErr := ssh.Unmarshal(payload, &ptyReq); uErr != nil {
			si.Logger.Debugf(si.LogPrefix + "Failed to unmarshall \"pty-req\" request")
		}
		si.Logger.Debugf(si.LogPrefix+"Init Terminal size: %dx%d", ptyReq.TermWidthCols, ptyReq.TermHeightRows)

		initSize, uErr := json.Marshal(
			&types.TermDimensions{
				Width:  ptyReq.TermWidthCols,
				Height: ptyReq.TermHeightRows,
				X:      ptyReq.TermWidthPixels,
				Y:      ptyReq.TermHeightPixels,
			},
		)
		if uErr != nil {
			si.Logger.Debugf(si.LogPrefix + "Failed to marshal \"init-size\" request payload")
		}

		sliderClientChannel, requests, oErr := si.sshSessionConn.OpenChannel("init-size", initSize)
		if oErr != nil {
			si.Logger.Errorf(si.LogPrefix+"Failed to open SSH channel: %v", oErr)
			return
		}
		defer func() { _ = sliderClientChannel.Close() }()

		go ssh.DiscardRequests(requests)
	}

}

func (si *Config) ExecuteCommand(command string, initState *term.State) error {
	// Build command payload
	cmdLen := len(command)
	cmdBytes := []byte(command)
	payload := []byte{0, 0, 0, byte(cmdLen)}
	payload = append(payload, cmdBytes...)

	sliderClientChannel, shellRequests, oErr := si.sshSessionConn.OpenChannel("exec", payload)
	if oErr != nil {
		return fmt.Errorf("could not open ssh channel - %v", oErr)
	}
	defer func() { _ = sliderClientChannel.Close() }()

	go ssh.DiscardRequests(shellRequests)

	var envCloser struct{ Key, Value string }
	envCloser.Key = "SLIDER_ENV"
	envCloser.Value = "true"
	envVarList := append(si.envVarList, envCloser)

	// Handle environment variable events
	go func() {
		for _, envVar := range envVarList {
			if _, eErr := sliderClientChannel.SendRequest("env", true, ssh.Marshal(envVar)); eErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Failed to send env request - %v", eErr)
			}
		}
	}()
	state, _ := term.GetState(int(os.Stdin.Fd()))
	if rErr := term.Restore(int(os.Stdin.Fd()), initState); rErr != nil {
		return rErr
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), state) }()

	// Capture interrupt signal once to simulate that we can actually interact with a CTR^C
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		for range sig {
			// Stop capture
			signal.Stop(sig)
			close(sig)
			// Manually write SIGQUIT to the channel to stop the process
			_, _ = sliderClientChannel.Write([]byte{0x03})
		}
	}()

	_, _ = io.Copy(os.Stdout, sliderClientChannel)

	return nil
}

func (si *Config) channelPipe(sessionClientChannel ssh.Channel, channelType string, payload []byte) {
	sliderClientChannel, shellRequests, oErr := si.sshSessionConn.OpenChannel(channelType, payload)
	if oErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to open SSH channel: %v", oErr)
		return
	}
	defer func() { _ = sliderClientChannel.Close() }()

	// Handle requests from the SSH channel
	go si.handleRequests(sessionClientChannel, shellRequests, sliderChannelScope)
	// Pipe SSH channel with SSH channel
	_, _ = sio.PipeWithCancel(sessionClientChannel, sliderClientChannel)
}

func (si *Config) interactiveChannelPipe(sessionClientChannel ssh.Channel, channelType string, payload []byte, winChange chan []byte, envChange chan []byte) {
	sliderClientChannel, shellRequests, oErr := si.sshSessionConn.OpenChannel(channelType, payload)
	if oErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to open SSH channel: %v", oErr)
		return
	}
	defer func() { _ = sliderClientChannel.Close() }()

	// Handle window-change events
	go func() {
		for sizeBytes := range winChange {
			_, wErr := sliderClientChannel.SendRequest("window-change", true, sizeBytes)
			if wErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Failed to send window-change request - %v", wErr)
			}

		}
	}()
	// Handle environment variable events
	go func() {
		for envVarBytes := range envChange {
			_, eErr := sliderClientChannel.SendRequest("env", true, envVarBytes)
			if eErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Failed to send env request - %v", eErr)
			}
		}
	}()
	// Handle requests from the SSH channel
	go si.handleRequests(sessionClientChannel, shellRequests, sliderChannelScope)
	// Pipe SSH channel with SSH channel
	_, _ = sio.PipeWithCancel(sessionClientChannel, sliderClientChannel)
}

func (si *Config) interactiveConnPipe(conn net.Conn, channelType string, payload []byte, winChange chan []byte, envChange chan []byte) {
	sliderClientChannel, shellRequests, oErr := si.sshSessionConn.OpenChannel(channelType, payload)
	if oErr != nil {
		si.Logger.Errorf(si.LogPrefix+"Failed to open SSH channel: %v", oErr)
		return
	}
	defer func() { _ = sliderClientChannel.Close() }()

	// Handle window-change events
	go func() {
		for sizeBytes := range winChange {
			_, wErr := sliderClientChannel.SendRequest("window-change", true, sizeBytes)
			if wErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Failed to send window-change request - %v", wErr)
			}

		}
	}()
	var envCloser struct{ Key, Value string }
	envCloser.Key = "SLIDER_ENV"
	envCloser.Value = "true"
	envCloserBytes := ssh.Marshal(envCloser)
	envChange <- envCloserBytes
	// Handle environment variable events
	go func() {
		for envVarBytes := range envChange {
			_, eErr := sliderClientChannel.SendRequest("env", true, envVarBytes)
			if eErr != nil {
				si.Logger.Errorf(si.LogPrefix+"Failed to send env request - %v", eErr)
			}
		}
	}()
	// Handle requests from the SSH channel
	go ssh.DiscardRequests(shellRequests)

	// Pipe SSH channel with SSH channel
	_, _ = sio.PipeWithCancel(conn, sliderClientChannel)
}

func (si *Config) IsEnabled() bool {
	si.instanceMutex.Lock()
	enabled := si.enabled
	si.instanceMutex.Unlock()
	return enabled
}

func (si *Config) isExposed() bool {
	si.instanceMutex.Lock()
	exposed := si.exposePort
	si.instanceMutex.Unlock()
	return exposed
}

func (si *Config) IsTLSOn() bool {
	si.instanceMutex.Lock()
	tlsOn := si.tlsOn
	si.instanceMutex.Unlock()
	return tlsOn
}

func (si *Config) GetEndpointPort() (int, error) {
	if !si.IsEnabled() {
		return 0, fmt.Errorf("endpoint is not running")
	}

	return si.port, nil
}

func (si *Config) Stop() error {
	if !si.IsEnabled() {
		return fmt.Errorf("endpoint is not running")
	}
	si.Logger.Debugf(si.LogPrefix + "Triggering Shutdown")

	si.stopSignal <- true
	<-si.done
	close(si.done)

	si.instanceMutex.Lock()
	si.port = 0
	si.enabled = false
	if si.interactiveOn {
		si.interactiveOn = false
	}
	si.instanceMutex.Unlock()

	si.Logger.Debugf(si.LogPrefix + "Endpoint down")

	return nil
}

func (si *Config) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if fp == si.allowedFingerprint {
		si.Logger.Debugf(si.LogPrefix+"Authenticated Client %s fingerprint: %s", conn.RemoteAddr(), fp)
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}
	si.Logger.Warnf(si.LogPrefix+"Rejected client %s, due to bad key authentication", conn.RemoteAddr())

	return nil, fmt.Errorf("client key not authorized")
}

// ParseSizePayload takes a byte slice as received from an SSH request and returns the width and height of the terminal
func ParseSizePayload(sizeBytes []byte) (uint32, uint32) {
	// First 4 bytes are width (cols), next 4 bytes are height (rows)
	cols := binary.BigEndian.Uint32(sizeBytes)
	rows := binary.BigEndian.Uint32(sizeBytes[4:])
	return cols, rows
}
