package instance

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slider/pkg/instance/portforward"
	"slider/pkg/instance/shell"
	"slider/pkg/instance/socks"
	"slider/pkg/instance/sshservice"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const (
	sshClientScope     = "ssh-client"
	sshSessionScope    = "ssh-session"
	sliderChannelScope = "slider-channel"
	SocksEndpoint      = "socks-endpoint"
	ShellEndpoint      = "shell-endpoint"
	SshEndpoint        = "ssh-endpoint"
	ExecEndpoint       = "exec-endpoint"
)

// ChannelOpener defines the interface required to open channels and send requests
// This allows abstracting specific SSH connections (like direct ssh.Conn or our custom RemoteConnection)
type ChannelOpener interface {
	OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}

type Config struct {
	Logger               *slog.Logger
	SessionID            int64
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
	sshSessionConn       ChannelOpener
	sshClientChannel     <-chan ssh.NewChannel
	EndpointType         string
	tlsOn                bool
	interactiveOn        bool
	CertificateAuthority *scrypt.CertificateAuthority
	certExists           bool
	serverCertificate    *scrypt.GeneratedCertificate
	envVarList           []struct{ Key, Value string }
	portFwdManager       *portforward.Manager
	socksClient          *socks.Client
	serviceManager       *ServiceManager
	shellService         *shell.Service
	sshService           *sshservice.Service
}

func New(config *Config) *Config {
	c := config
	c.envVarList = make([]struct{ Key, Value string }, 0)

	// Initialize ServiceManager
	c.serviceManager = NewServiceManager()

	// Initialize port forwarding manager and SOCKS client
	if c.sshSessionConn != nil {
		c.portFwdManager = portforward.NewManager(c.Logger, c.SessionID, c.sshSessionConn)
		c.socksClient = socks.NewClient(c.Logger, c.SessionID, c.sshSessionConn)
		c.shellService = shell.NewService(c.Logger, c.SessionID, c.sshSessionConn)

		// Register services with ServiceManager
		_ = c.serviceManager.RegisterService(c.socksClient)
		_ = c.serviceManager.RegisterService(c.shellService)
	}

	// Initialize SSH service if ServerKey is available
	if c.ServerKey != nil {
		c.sshService = sshservice.NewService(&sshservice.Config{
			Logger:             c.Logger,
			SessionID:          c.SessionID,
			ServerKey:          c.ServerKey,
			AuthOn:             c.AuthOn,
			AllowedFingerprint: c.allowedFingerprint,
			PtyOn:              c.ptyOn,
			PortFwdManager:     c.portFwdManager,
		})
		_ = c.serviceManager.RegisterService(c.sshService)
	}

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

func (si *Config) SetSSHConn(conn ChannelOpener) {
	si.instanceMutex.Lock()
	si.sshSessionConn = conn
	// Initialize or update port forwarding manager and SOCKS client when connection is set
	if si.portFwdManager == nil {
		si.portFwdManager = portforward.NewManager(si.Logger, si.SessionID, conn)
	}
	if si.socksClient == nil {
		si.socksClient = socks.NewClient(si.Logger, si.SessionID, conn)
		_ = si.serviceManager.RegisterService(si.socksClient)
	}
	if si.shellService == nil {
		si.shellService = shell.NewService(si.Logger, si.SessionID, conn)
		_ = si.serviceManager.RegisterService(si.shellService)
	}
	si.instanceMutex.Unlock()
}

func (si *Config) GetPortForwardManager() *portforward.Manager {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	return si.portFwdManager
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
		return fmt.Errorf("can not listen for connections: %v", lErr)
	}
	if !si.isExposed() {
		_ = listener.Close()
		listener, lErr = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if lErr != nil {
			return fmt.Errorf("can not listen for localhost connections: %v", lErr)
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

	si.Logger.DebugWith("Triggering Listener",
		slog.F("session_id", si.SessionID),
		slog.F("port", port))
	for {
		conn, aErr := listener.Accept()
		if aErr != nil {
			break
		}

		// Map endpoint types to service types
		var serviceType string
		switch si.EndpointType {
		case SocksEndpoint:
			serviceType = "socks"
			go si.handleServiceConnection(serviceType, conn)
		case ShellEndpoint:
			serviceType = "shell"
			go si.handleServiceConnection(serviceType, conn)
		case SshEndpoint:
			// SSH endpoint still uses the original logic due to its complexity
			go si.runSshComm(conn)
		default:
			return fmt.Errorf("unknown endpoint type \"%s\"", si.EndpointType)
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
		si.Logger.ErrorWith("Failed SSH handshake",
			slog.F("session_id", si.SessionID),
			slog.F("err", cErr))
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
				si.Logger.ErrorWith("Failed to accept channel",
					slog.F("session_id", si.SessionID),
					slog.F("channel_type", nc.ChannelType()),
					slog.F("err", aErr))
			}
			go si.handleRequests(sessionClientChannel, request, sshSessionScope)
		case "direct-tcpip":
			go func() {
				if hErr := si.handleDirectTcpIpChannel(nc); hErr != nil {
					si.Logger.ErrorWith("Failed to handle channel",
						slog.F("session_id", si.SessionID),
						slog.F("channel_type", nc.ChannelType()),
						slog.F("err", hErr))
				}
			}()
		default:
			si.Logger.WarnWith("SSH Rejected channel type",
				slog.F("session_id", si.SessionID),
				slog.F("channel_type", nc.ChannelType()),
				slog.F("payload", nc.ExtraData()))
			_ = nc.Reject(ssh.UnknownChannelType, "")
		}
	}
}

func (si *Config) runShellComm(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	width, height, tErr := term.GetSize(int(os.Stdout.Fd()))
	if tErr != nil {
		si.Logger.ErrorWith("Failed to get terminal size",
			slog.F("session_id", si.SessionID),
			slog.F("err", tErr))
		return
	}

	initSize, uErr := json.Marshal(
		&types.TermDimensions{
			Width:  uint32(width),
			Height: uint32(height),
		},
	)
	if uErr != nil {
		si.Logger.ErrorWith("Failed to marshal init terminal size",
			slog.F("session_id", si.SessionID),
			slog.F("err", uErr))
		return
	}

	// Send message with initial size
	initChan, reqs, oErr := si.sshSessionConn.OpenChannel("init-size", initSize)
	if oErr != nil {
		si.Logger.ErrorWith("Failed to open channel",
			slog.F("session_id", si.SessionID),
			slog.F("channel_type", "init-size"),
			slog.F("err", oErr))
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

// handleServiceConnection dispatches a connection to the appropriate service via ServiceManager
func (si *Config) handleServiceConnection(serviceType string, conn net.Conn) {
	if err := si.serviceManager.HandleConnection(serviceType, conn); err != nil {
		si.Logger.ErrorWith("Failed to handle service connection",
			slog.F("session_id", si.SessionID),
			slog.F("service_type", serviceType),
			slog.F("err", err))
		_ = conn.Close()
	}
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
			si.Logger.DebugWith("Scope \"%s\" - Request Type \"%s\" - payload: %v",
				slog.F("session_id", si.SessionID),
				slog.F("scope", scope),
				slog.F("request_type", req.Type),
				slog.F("payload", req.Payload))
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
			si.Logger.DebugWith("Request status",
				slog.F("session_id", si.SessionID),
				slog.F("request_type", req.Type),
				slog.F("request_status", ok),
				slog.F("payload", req.Payload))
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		}
	}
}

func (si *Config) TcpIpForwardFromMsg(msg types.CustomTcpIpChannelMsg, notifier chan error) {
	if si.portFwdManager == nil {
		notifier <- fmt.Errorf("port forwarding manager not initialized")
		return
	}
	si.portFwdManager.StartRemoteForward(msg, notifier)
}

func (si *Config) GetLocalMappings() map[int]*portforward.LocalForward {
	if si.portFwdManager == nil {
		return make(map[int]*portforward.LocalForward)
	}
	return si.portFwdManager.GetLocalMappings()
}

func (si *Config) GetLocalPortMapping(port int) (*portforward.LocalForward, error) {
	if si.portFwdManager == nil {
		return nil, fmt.Errorf("port forwarding manager not initialized")
	}
	return si.portFwdManager.GetLocalMapping(port)
}

func (si *Config) DirectTcpIpFromMsg(msg types.TcpIpChannelMsg, notifier chan error) {
	if si.portFwdManager == nil {
		notifier <- fmt.Errorf("port forwarding manager not initialized")
		return
	}
	si.portFwdManager.StartLocalForward(msg, notifier)
}

func (si *Config) handleTcpIpForwardRequest(req *ssh.Request) {
	if si.portFwdManager == nil {
		si.Logger.ErrorWith("Port forwarding manager not initialized",
			slog.F("session_id", si.SessionID))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}
	si.portFwdManager.HandleTcpIpForwardRequest(req, si.sshServerConn)
}

func (si *Config) GetRemoteMappings() map[int]*portforward.RemoteForward {
	if si.portFwdManager == nil {
		return make(map[int]*portforward.RemoteForward)
	}
	return si.portFwdManager.GetRemoteMappings()
}

func (si *Config) GetRemotePortMapping(port int) (*portforward.RemoteForward, error) {
	if si.portFwdManager == nil {
		return nil, fmt.Errorf("port forwarding manager not initialized")
	}
	return si.portFwdManager.GetRemoteMapping(port)
}

func (si *Config) cancelSshRemoteFwd() {
	if si.portFwdManager != nil {
		si.portFwdManager.CancelAllSSHRemoteForwards()
	}
}

func (si *Config) CancelMsgRemoteFwd(port int) error {
	if si.portFwdManager == nil {
		return fmt.Errorf("port forwarding manager not initialized")
	}
	return si.portFwdManager.CancelRemoteForward(port)
}

func (si *Config) handleDirectTcpIpChannel(nc ssh.NewChannel) error {
	if si.portFwdManager == nil {
		return fmt.Errorf("port forwarding manager not initialized")
	}
	return si.portFwdManager.HandleDirectTcpIpChannel(nc)
}

// sendInitTermSize receives a req-pty payload extracts the terminal size and sends it through an init-size channel payload
func (si *Config) sendInitTermSize(payload []byte) {
	// Do not panic if payload happens to be empty
	if len(payload) > 0 {
		var ptyReq types.PtyRequest
		if uErr := ssh.Unmarshal(payload, &ptyReq); uErr != nil {
			si.Logger.ErrorWith("Failed to unmarshall \"pty-req\" request",
				slog.F("session_id", si.SessionID),
				slog.F("request_type", "pty-req"),
				slog.F("err", uErr))
		}
		si.Logger.DebugWith("Init Terminal size",
			slog.F("session_id", si.SessionID),
			slog.F("request_type", "pty-req"),
			slog.F("width", ptyReq.TermWidthCols),
			slog.F("height", ptyReq.TermHeightRows))

		initSize, uErr := json.Marshal(
			&types.TermDimensions{
				Width:  ptyReq.TermWidthCols,
				Height: ptyReq.TermHeightRows,
				X:      ptyReq.TermWidthPixels,
				Y:      ptyReq.TermHeightPixels,
			},
		)
		if uErr != nil {
			si.Logger.ErrorWith("Failed to marshal request payload",
				slog.F("session_id", si.SessionID),
				slog.F("request_type", "init-size"),
				slog.F("err", uErr))
		}

		sliderClientChannel, requests, oErr := si.sshSessionConn.OpenChannel("init-size", initSize)
		if oErr != nil {
			si.Logger.ErrorWith("Failed to open SSH channel",
				slog.F("session_id", si.SessionID),
				slog.F("channel_type", "init-size"),
				slog.F("err", oErr))
			return
		}
		defer func() { _ = sliderClientChannel.Close() }()

		go ssh.DiscardRequests(requests)
	}

}

func (si *Config) ExecuteCommand(command string, initState *term.State) error {
	// Check if SSH connection is available
	if si.sshSessionConn == nil {
		return fmt.Errorf("no active SSH connection available")
	}

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
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", "env"),
					slog.F("err", eErr))
			}
		}
	}()
	state, _ := term.GetState(int(os.Stdin.Fd()))
	if rErr := term.Restore(int(os.Stdin.Fd()), initState); rErr != nil {
		return rErr
	}
	defer func() { _ = term.Restore(int(os.Stdin.Fd()), state) }()

	// Capture interrupt signal for Ctrl+C handling
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
		si.Logger.ErrorWith("Failed to open SSH channel",
			slog.F("session_id", si.SessionID),
			slog.F("channel_type", channelType),
			slog.F("err", oErr))
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
		si.Logger.ErrorWith("Failed to open SSH channel",
			slog.F("session_id", si.SessionID),
			slog.F("channel_type", channelType),
			slog.F("err", oErr))
		return
	}
	defer func() { _ = sliderClientChannel.Close() }()

	// Handle window-change events
	go func() {
		for sizeBytes := range winChange {
			_, wErr := sliderClientChannel.SendRequest("window-change", true, sizeBytes)
			if wErr != nil {
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", "window-change"),
					slog.F("err", wErr))
			}

		}
	}()
	// Handle environment variable events
	go func() {
		for envVarBytes := range envChange {
			_, eErr := sliderClientChannel.SendRequest("env", true, envVarBytes)
			if eErr != nil {
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", "env"),
					slog.F("err", eErr))
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
		si.Logger.ErrorWith("Failed to open SSH channel",
			slog.F("session_id", si.SessionID),
			slog.F("channel_type", channelType),
			slog.F("err", oErr))
		return
	}
	defer func() { _ = sliderClientChannel.Close() }()

	// Handle window-change events
	go func() {
		for sizeBytes := range winChange {
			_, wErr := sliderClientChannel.SendRequest("window-change", true, sizeBytes)
			if wErr != nil {
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", "window-change"),
					slog.F("err", wErr))
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
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", "env"),
					slog.F("err", eErr))
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
	si.Logger.DebugWith("Triggering Shutdown",
		slog.F("session_id", si.SessionID),
		slog.F("endpoint_type", si.EndpointType))

	si.stopSignal <- true
	<-si.done
	close(si.done)

	// Stop all services managed by ServiceManager
	if si.serviceManager != nil {
		if err := si.serviceManager.StopAll(); err != nil {
			si.Logger.WarnWith("Failed to stop all services",
				slog.F("session_id", si.SessionID),
				slog.F("err", err))
		}
	}

	si.instanceMutex.Lock()
	si.port = 0
	si.enabled = false
	if si.interactiveOn {
		si.interactiveOn = false
	}
	si.instanceMutex.Unlock()

	si.Logger.DebugWith("Endpoint down",
		slog.F("session_id", si.SessionID),
		slog.F("endpoint_type", si.EndpointType))

	return nil
}

func (si *Config) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if fp == si.allowedFingerprint {
		si.Logger.DebugWith("Authenticated Client",
			slog.F("session_id", si.SessionID),
			slog.F("remote_addr", conn.RemoteAddr()),
			slog.F("fingerprint", fp))
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}
	si.Logger.DebugWith("Rejected client",
		slog.F("session_id", si.SessionID),
		slog.F("remote_addr", conn.RemoteAddr()),
		slog.F("err", "bad key authentication"))

	return nil, fmt.Errorf("client key not authorized")
}

// ParseSizePayload takes a byte slice as received from an SSH request and returns the width and height of the terminal
func ParseSizePayload(sizeBytes []byte) (uint32, uint32) {
	// First 4 bytes are width (cols), next 4 bytes are height (rows)
	cols := binary.BigEndian.Uint32(sizeBytes)
	rows := binary.BigEndian.Uint32(sizeBytes[4:])
	return cols, rows
}
