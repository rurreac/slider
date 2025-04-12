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
	"sync"
	"syscall"
)

const (
	sshClientScope     = "ssh-client"
	sshSessionScope    = "ssh-session"
	sliderChannelScope = "slider-channel"
	SocksOnly          = "socks"
	ShellOnly          = "shell"
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
	sshMutex             sync.Mutex
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
}

// PTYRequest is the structure of a message for
// a "pty-req" as described in RFC4254
type PTYRequest struct {
	TermEnvVar       string
	TermWidthCols    uint32
	TermHeightRows   uint32
	TermWidthPixels  uint32
	TermHeightPixels uint32
	TerminalModes    string
}

// DirectTCPIP is the structure of a message for
// a "direct-tcpip" as described in RFC4254
type DirectTCPIP struct {
	DstHost string
	DstPort uint32
	SrcHost string
	SrcPort uint32
}

func New(config *Config) *Config {
	return config
}

func (si *Config) SetExpose(expose bool) {
	si.sshMutex.Lock()
	si.exposePort = expose
	si.sshMutex.Unlock()
}

func (si *Config) SetPtyOn(ptyOn bool) {
	si.sshMutex.Lock()
	si.ptyOn = ptyOn
	si.sshMutex.Unlock()
}

func (si *Config) setControls() {
	si.sshMutex.Lock()
	si.stopSignal = make(chan bool, 1)
	si.done = make(chan bool, 1)
	si.sshMutex.Unlock()
}

func (si *Config) SetSSHConn(conn ssh.Conn) {
	si.sshMutex.Lock()
	si.sshSessionConn = conn
	si.sshMutex.Unlock()
}

func (si *Config) setPort(port int) {
	si.sshMutex.Lock()
	si.port = port
	si.enabled = true
	si.sshMutex.Unlock()
}

func (si *Config) setServerCertificate(cert *scrypt.GeneratedCertificate) {
	si.sshMutex.Lock()
	si.certExists = true
	si.serverCertificate = cert
	si.sshMutex.Unlock()
}

func (si *Config) SetTLSOn(tlsOn bool) {
	si.sshMutex.Lock()
	si.tlsOn = tlsOn
	si.sshMutex.Unlock()
}

func (si *Config) SetInteractiveOn(interactiveOn bool) {
	si.sshMutex.Lock()
	si.interactiveOn = interactiveOn
	si.sshMutex.Unlock()
}

func (si *Config) SetAllowedFingerprint(fp string) {
	si.sshMutex.Lock()
	si.allowedFingerprint = fp
	si.sshMutex.Unlock()
}

func (si *Config) SetEnvVarList(evl []struct{ Key, Value string }) {
	si.sshMutex.Lock()
	si.envVarList = evl
	si.sshMutex.Unlock()
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
		case SocksOnly:
			go si.runSocksComm(conn)
		case ShellOnly:
			go si.runShellComm(conn)
		default:
			go si.runComm(conn)
		}

	}

	si.done <- true
	return nil
}

func (si *Config) runComm(conn net.Conn) {
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
	defer func() { _ = si.sshServerConn.Close() }()

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
				if hErr := si.handleSocksChannel(nc); hErr != nil {
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
		&conf.TermDimensions{
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
		default:
			si.Logger.Debugf(si.LogPrefix+"Request status: %v - type: %s - payload: %s", ok, req.Type, req.Payload)
			if req.WantReply {
				go func() { _ = req.Reply(ok, nil) }()
			}
		}
	}
}

func (si *Config) handleSocksChannel(nc ssh.NewChannel) error {
	sessionClientChannel, request, aErr := nc.Accept()
	if aErr != nil {
		return fmt.Errorf("could not accept channel - %v", aErr)
	}
	defer func() { _ = sessionClientChannel.Close() }()
	go ssh.DiscardRequests(request)

	var dti DirectTCPIP
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
		var ptyReq PTYRequest
		if uErr := ssh.Unmarshal(payload, &ptyReq); uErr != nil {
			si.Logger.Debugf(si.LogPrefix + "Failed to unmarshall \"pty-req\" request")
		}
		si.Logger.Debugf(si.LogPrefix+"Init Terminal size: %dx%d", ptyReq.TermWidthCols, ptyReq.TermHeightRows)

		initSize, uErr := json.Marshal(
			&conf.TermDimensions{
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
	state, _ := term.GetState(int(os.Stdout.Fd()))
	if rErr := term.Restore(int(os.Stdout.Fd()), initState); rErr != nil {
		return rErr
	}
	defer func() { _ = term.Restore(int(os.Stdout.Fd()), state) }()

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
	si.sshMutex.Lock()
	enabled := si.enabled
	si.sshMutex.Unlock()
	return enabled
}

func (si *Config) isExposed() bool {
	si.sshMutex.Lock()
	exposed := si.exposePort
	si.sshMutex.Unlock()
	return exposed
}

func (si *Config) IsTLSOn() bool {
	si.sshMutex.Lock()
	tlsOn := si.tlsOn
	si.sshMutex.Unlock()
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

	si.sshMutex.Lock()
	si.port = 0
	si.enabled = false
	if si.interactiveOn {
		si.interactiveOn = false
	}
	si.sshMutex.Unlock()

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
