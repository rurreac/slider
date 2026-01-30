package instance

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"slider/pkg/conf"
	"slider/pkg/instance/portforward"
	"slider/pkg/instance/shell"
	"slider/pkg/instance/socks"
	"slider/pkg/instance/sshservice"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync"

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
	Wait() error
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
	useAltShell          bool
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
	defer si.instanceMutex.Unlock()

	si.sshSessionConn = conn

	// Always recreate services with the new connection
	si.portFwdManager = portforward.NewManager(si.Logger, si.SessionID, conn)
	si.socksClient = socks.NewClient(si.Logger, si.SessionID, conn)
	si.shellService = shell.NewService(si.Logger, si.SessionID, conn)

	// Register services with the service manager
	_ = si.serviceManager.RegisterService(si.socksClient)
	_ = si.serviceManager.RegisterService(si.shellService)
}

// GetSSHConn returns the SSH connection
func (si *Config) GetSSHConn() ChannelOpener {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	return si.sshSessionConn
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

func (si *Config) SetUseAltShell(useAltShell bool) {
	si.instanceMutex.Lock()
	si.useAltShell = useAltShell
	if si.shellService != nil {
		si.shellService.SetUseAltShell(useAltShell)
	}
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

func (si *Config) SetInitTermSize(size types.TermDimensions) {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	if si.shellService != nil {
		si.shellService.SetInitTermSize(size)
	}
}

func (si *Config) Resize(cols, rows uint32) {
	si.instanceMutex.Lock()
	defer si.instanceMutex.Unlock()
	if si.shellService != nil {
		si.shellService.Resize(cols, rows)
	}
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
		// Wait for stop signal
		<-si.stopSignal
		_ = listener.Close()
	}()

	// Helper function for safe access
	getSSHConn := func() ChannelOpener {
		si.instanceMutex.Lock()
		defer si.instanceMutex.Unlock()
		// Make a copy or return interface
		return si.sshSessionConn
	}

	// Monitor the underlying connection
	go func() {
		conn := getSSHConn()
		if conn != nil {
			_ = conn.Wait()
			// Connection closed or errored, stop the listener
			si.Logger.DebugWith("Triggering listener cleanup signal",
				slog.F("session_id", si.SessionID),
				slog.F("port", port))

			// Ensure Port Forwarding is also cleaned up
			if si.portFwdManager != nil {
				si.portFwdManager.CloseAll()
			}

			si.stopSignal <- true
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
		case conf.SSHChannelSession:
			sessionClientChannel, request, aErr := nc.Accept()
			if aErr != nil {
				si.Logger.ErrorWith("Failed to accept channel",
					slog.F("session_id", si.SessionID),
					slog.F("channel_type", nc.ChannelType()),
					slog.F("err", aErr))
			}
			go si.handleRequests(sessionClientChannel, request, sshSessionScope)
		case conf.SSHChannelDirectTCPIP:
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

	sshConn := si.GetSSHConn()
	if sshConn == nil {
		si.Logger.ErrorWith("SSH connection not set on endpoint instance",
			slog.F("session_id", si.SessionID))
		return
	}

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
	initChan, reqs, oErr := sshConn.OpenChannel(conf.SSHChannelInitSize, initSize)
	if oErr != nil {
		si.Logger.ErrorWith("Failed to open channel",
			slog.F("session_id", si.SessionID),
			slog.F("channel_type", conf.SSHChannelInitSize),
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

	// Local PTY tracking for this connection
	var externalPtyRequested bool

	for req := range requests {
		ok := false
		if req.Type != conf.SSHRequestEnv {
			si.Logger.DebugWith("External request received",
				slog.F("session_id", si.SessionID),
				slog.F("scope", scope),
				slog.F("request_type", req.Type),
				slog.F("payload", req.Payload))
		}
		switch req.Type {
		case conf.SSHRequestPTY:
			// Answering pty-req request true if Slider client has ptyOn
			if si.ptyOn {
				ok = true
				// Track that external client requested PTY for this connection
				externalPtyRequested = true
				// Process req-pty info to Slider client through a new channel "init-size"
				si.sendInitTermSize(req.Payload)
			}
			if req.WantReply {
				go func() {
					_ = req.Reply(ok, nil)
				}()
			}
		case conf.SSHRequestEnv:
			ok = true
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			envChange <- req.Payload
		case conf.SSHRequestShell:
			ok = true
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}

			// Send environment variables to channel
			for _, envVar := range si.getEnvVars(externalPtyRequested) {
				envChange <- ssh.Marshal(envVar)
			}
			go si.interactiveChannelPipe(sessionClientChannel, req.Type, nil, winChange, envChange)
		case conf.SSHRequestExec:
			ok = true
			if req.WantReply {
				go func() {
					_ = req.Reply(ok, nil)
				}()
			}

			// Send environment variables to channel
			for _, envVar := range si.getEnvVars(externalPtyRequested) {
				envChange <- ssh.Marshal(envVar)
			}
			go si.interactiveChannelPipe(sessionClientChannel, req.Type, req.Payload, winChange, envChange)
		case conf.SSHRequestWindowChange:
			if si.ptyOn {
				ok = true
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
			winChange <- req.Payload
		case conf.SSHRequestSubsystem:
			if string(req.Payload[4:]) == conf.SSHChannelSFTP {
				ok = true
				go si.channelPipe(sessionClientChannel, conf.SSHChannelSFTP, nil)
			}
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		case conf.SSHRequestTcpIpForward:
			go si.handleTcpIpForwardRequest(req)
		case conf.SSHRequestKeepAlive:
			ok = true
			if req.WantReply {
				go func() {
					_ = req.Reply(ok, nil)
				}()
			}
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

func (si *Config) getEnvVars(externalPtyRequested bool) []struct{ Key, Value string } {
	var envVarList []struct{ Key, Value string }
	// Request alternate shell if enabled
	if si.useAltShell {
		var altC struct{ Key, Value string }
		altC.Key = conf.SliderAltShellEnvVar
		altC.Value = "true"
		envVarList = append(envVarList, altC)
	}
	// Always request PTY for Console execute command
	if externalPtyRequested {
		var ptySignal struct{ Key, Value string }
		ptySignal.Key = conf.SliderExecPtyEnvVar
		ptySignal.Value = "true"
		envVarList = append(envVarList, ptySignal)
	}

	// Always send closer env var
	var envCloser struct{ Key, Value string }
	envCloser.Key = conf.SliderCloserEnvVar
	envCloser.Value = "true"
	envVarList = append(envVarList, envCloser)

	return envVarList
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
	sshConn := si.GetSSHConn()
	if sshConn == nil {
		si.Logger.ErrorWith("SSH connection not set on endpoint instance",
			slog.F("session_id", si.SessionID))
		return
	}

	// Do not panic if payload happens to be empty
	if len(payload) > 0 {
		var ptyReq types.PtyRequest
		if uErr := ssh.Unmarshal(payload, &ptyReq); uErr != nil {
			si.Logger.ErrorWith("Failed to unmarshall \"pty-req\" request",
				slog.F("session_id", si.SessionID),
				slog.F("request_type", conf.SSHRequestPTY),
				slog.F("err", uErr))
		}
		si.Logger.DebugWith("Init Terminal size",
			slog.F("session_id", si.SessionID),
			slog.F("request_type", conf.SSHRequestPTY),
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
				slog.F("request_type", conf.SSHChannelInitSize),
				slog.F("err", uErr))
		}

		sliderClientChannel, requests, oErr := sshConn.OpenChannel(conf.SSHChannelInitSize, initSize)
		if oErr != nil {
			si.Logger.ErrorWith("Failed to open SSH channel",
				slog.F("session_id", si.SessionID),
				slog.F("channel_type", conf.SSHChannelInitSize),
				slog.F("err", oErr))
			return
		}
		defer func() { _ = sliderClientChannel.Close() }()

		go ssh.DiscardRequests(requests)
	}

}

func (si *Config) ExecuteCommand(cmdBytes []byte, ic io.ReadWriter) error {
	sshConn := si.GetSSHConn()
	if sshConn == nil {
		return fmt.Errorf("no active SSH connection available")
	}

	// Build command payload
	cmdLen := len(string(cmdBytes))
	payload := []byte{0, 0, 0, byte(cmdLen)}
	payload = append(payload, cmdBytes...)

	sliderClientChannel, shellRequests, oErr := sshConn.OpenChannel(conf.SSHRequestExec, payload)
	if oErr != nil {
		return fmt.Errorf("could not open ssh channel: %v", oErr)
	}
	defer func() { _ = sliderClientChannel.Close() }()

	go ssh.DiscardRequests(shellRequests)

	// Handle environment variable events
	go func() {
		// Always request PTY for Console execute commands
		for _, envVar := range si.getEnvVars(true) {
			if _, eErr := sliderClientChannel.SendRequest(conf.SSHRequestEnv, true, ssh.Marshal(envVar)); eErr != nil {
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", conf.SSHRequestEnv),
					slog.F("err", eErr))
			}
		}
	}()

	// Signal channel to stop stdin reader when the connection errors/closes
	done := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(2)

	// Remote -> Local: copy from connection to stdout
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ic, sliderClientChannel)
		// Signal stdin reader to stop
		close(done)
	}()

	// Local -> Remote: cancellable stdin copy using select(2)
	go func() {
		defer wg.Done()
		sio.CopyInteractiveCancellable(sliderClientChannel, ic, done)
	}()

	wg.Wait()

	return nil
}

func (si *Config) channelPipe(sessionClientChannel ssh.Channel, channelType string, payload []byte) {
	sshConn := si.GetSSHConn()
	if sshConn == nil {
		si.Logger.ErrorWith("SSH connection not set on endpoint instance",
			slog.F("session_id", si.SessionID))
		return
	}

	sliderClientChannel, shellRequests, oErr := sshConn.OpenChannel(channelType, payload)
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
	sshConn := si.GetSSHConn()
	if sshConn == nil {
		si.Logger.ErrorWith("SSH connection not set on endpoint instance",
			slog.F("session_id", si.SessionID))
		return
	}

	sliderClientChannel, shellRequests, oErr := sshConn.OpenChannel(channelType, payload)
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
			_, wErr := sliderClientChannel.SendRequest(conf.SSHRequestWindowChange, true, sizeBytes)
			if wErr != nil {
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", conf.SSHRequestWindowChange),
					slog.F("err", wErr))
			}

		}
	}()

	// Handle environment variable events
	go func() {
		for envVarBytes := range envChange {
			_, eErr := sliderClientChannel.SendRequest(conf.SSHRequestEnv, true, envVarBytes)
			if eErr != nil {
				si.Logger.ErrorWith("Failed to send request",
					slog.F("session_id", si.SessionID),
					slog.F("request_type", conf.SSHRequestEnv),
					slog.F("err", eErr))
			}
		}
	}()

	// Send environment variables to channel
	for _, envVar := range si.getEnvVars(false) {
		envChange <- ssh.Marshal(envVar)
	}

	// Pipe external SSH session channel with Slider SSH channel
	byteTrx, byteRcv := si.channelPipeWithStatus(sessionClientChannel, sliderClientChannel, shellRequests)
	si.Logger.DebugWith("Pipe closed",
		slog.F("session_id", si.SessionID),
		slog.F("bytes_transferred", byteTrx),
		slog.F("bytes_received", byteRcv))

}

// pipeChannelWithStatus pipes data between an SSH client-server channel and a slider channel on shell/exec requests,
// forwarding the exit status request from slider to the SSH client so exit code is reported
func (si *Config) channelPipeWithStatus(sessionClientChannel ssh.Channel, sliderClientChannel ssh.Channel, shellRequests <-chan *ssh.Request) (int64, int64) {
	var byteTrx int64
	var byteRcv int64

	// Start bidirectional copy in background
	go func() {
		byteRcv, _ = io.Copy(sessionClientChannel, sliderClientChannel)
	}()
	go func() {
		byteTrx, _ = io.Copy(sliderClientChannel, sessionClientChannel)
	}()

	// Block on shellRequests which closes when the channel closes
	// Process exit-status and return immediately
	for req := range shellRequests {
		switch req.Type {
		case "exit-status":
			if sessionClientChannel != nil {
				_, _ = sessionClientChannel.SendRequest(req.Type, false, req.Payload)
			}
			// Close and return immediately
			_ = sessionClientChannel.Close()
			_ = sliderClientChannel.Close()
			return byteTrx, byteRcv
		}
		if req.WantReply {
			_ = req.Reply(true, nil)
		}
	}

	// Return on unexpected copy termination
	return byteTrx, byteRcv
}

func (si *Config) interactiveConnPipe(conn net.Conn, channelType string, payload []byte, winChange chan []byte, envChange chan []byte) {
	sshConn := si.GetSSHConn()
	if sshConn == nil {
		si.Logger.ErrorWith("SSH connection not set on endpoint instance",
			slog.F("session_id", si.SessionID))
		return
	}

	sliderClientChannel, shellRequests, oErr := sshConn.OpenChannel(channelType, payload)
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

	// Send environment variables to channel
	for _, envVar := range si.getEnvVars(false) {
		envChange <- ssh.Marshal(envVar)
	}

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
