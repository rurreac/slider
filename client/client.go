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
	"net/url"
	"os"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/sconn"
	"slider/pkg/scrypt"
	"slider/pkg/sflag"
	"slider/pkg/slog"
	"strings"
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
	serverURL         *url.URL
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
	*listenerConf
}

type listenerConf struct {
	urlRedirect  *url.URL
	templatePath string
	httpVersion  bool
	httpHealth   bool
	serverHeader string
	statusCode   int
}

const clientHelp = `
Slider Client

  Creates a new Slider Client instance and connects 
to the defined Slider Server.

Usage: <slider_client> [flags] [<[server_address]:port>]

Flags:`

var shutdown = make(chan bool, 1)

func NewClient(args []string) {
	defer close(shutdown)
	clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
	verbose := clientFlags.String("verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	keepalive := clientFlags.Duration("keepalive", conf.Keepalive, "Sets keepalive interval in seconds.")
	colorless := clientFlags.Bool("colorless", false, "Disables logging colors")
	fingerprint := clientFlags.String("fingerprint", "", "Server fingerprint for host verification (listener)")
	key := clientFlags.String("key", "", "Private key for authenticating to a Server")
	listener := clientFlags.Bool("listener", false, "Client will listen for incoming Server connections")
	port := clientFlags.Int("port", 8081, "Listener port")
	address := clientFlags.String("address", "0.0.0.0", "Address the Listener will bind to")
	retry := clientFlags.Bool("retry", false, "Retries reconnection indefinitely")
	templatePath := clientFlags.String("http-template", "", "Path of a default file to serve (listener)")
	serverHeader := clientFlags.String("http-server-header", "", "Sets a server header value (listener)")
	httpRedirect := clientFlags.String("http-redirect", "", "Redirects incoming HTTP to given URL (listener)")
	statusCode := clientFlags.Int("http-status-code", 200, "Template Status code [200|301|302|400|401|403|500|502|503] (listener)")
	httpVersion := clientFlags.Bool("http-version", false, "Enables /version HTTP path")
	httpHealth := clientFlags.Bool("http-health", false, "Enables /health HTTP path")
	customDNS := clientFlags.String("dns", "", "Uses custom DNS server <host[:port]> for resolving server address")
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
		listenerConf: &listenerConf{
			urlRedirect: &url.URL{},
			httpVersion: *httpVersion,
			httpHealth:  *httpHealth,
		},
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
	c.httpHeaders = http.Header{"Sec-WebSocket-Protocol": {conf.HttpVersionResponse.ProtoVersion}}

	if *listener {
		c.isListener = *listener
		c.listenerConf.serverHeader = *serverHeader

		if *templatePath != "" {
			tErr := conf.CheckTemplate(*templatePath)
			if tErr != nil {
				c.Logger.Fatalf("Wrong template: %s", tErr)
			}
			c.listenerConf.templatePath = *templatePath
		}

		c.listenerConf.statusCode = *statusCode
		if !conf.CheckStatusCode(*statusCode) {
			c.Logger.Warnf("Invalid status code \"%d\", will use \"%d\"", *statusCode, http.StatusOK)
			c.listenerConf.statusCode = http.StatusOK
		}

		if *httpRedirect != "" {
			wr, wErr := conf.ResolveURL(*httpRedirect)
			if wErr != nil {
				c.Logger.Fatalf("Bad Redirect URL: %v", wErr)
			}
			c.urlRedirect = wr
			c.Logger.Debugf("Redirecting incomming HTTP requests to \"%s\"", c.urlRedirect.String())
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
		serverURL := clientFlags.Args()[0]
		su, uErr := conf.ResolveURL(serverURL)
		if uErr != nil {
			c.Logger.Fatalf("Argument \"%s\" is not a valid URL", serverURL)
		}

		c.serverURL = su
		c.wsConfig = conf.DefaultWebSocketDialer

		for loop := true; loop; {
			c.startConnection(*customDNS)

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
	if sflag.FlagIsDefined(clientFlags, "listener") {
		clientType = "listener"
		if sflag.FlagIsDefined(clientFlags, "key") {
			flagExclusion = append(flagExclusion, "-key")
		}
		if sflag.FlagIsDefined(clientFlags, "retry") {
			flagExclusion = append(flagExclusion, "-retry")
		}
		if sflag.FlagIsDefined(clientFlags, "dns") {
			flagExclusion = append(flagExclusion, "-dns")
		}
		if len(clientFlags.Args()) > 0 {
			flagExclusion = append(flagExclusion, clientFlags.Args()...)
		}
	} else {
		clientType = "reverse"
		if sflag.FlagIsDefined(clientFlags, "fingerprint") {
			flagExclusion = append(flagExclusion, "-fingerprint")
		}
		if sflag.FlagIsDefined(clientFlags, "address") {
			flagExclusion = append(flagExclusion, "-address")
		}
		if sflag.FlagIsDefined(clientFlags, "port") {
			flagExclusion = append(flagExclusion, "-port")
		}
		if sflag.FlagIsDefined(clientFlags, "html-template") {
			flagExclusion = append(flagExclusion, "-html-template")
		}
		if sflag.FlagIsDefined(clientFlags, "html-server-header") {
			flagExclusion = append(flagExclusion, "-html-server-header")
		}
		if sflag.FlagIsDefined(clientFlags, "html-status-code") {
			flagExclusion = append(flagExclusion, "-html-status-code")
		}
		if sflag.FlagIsDefined(clientFlags, "html-redirect") {
			flagExclusion = append(flagExclusion, "-html-redirect")
		}
		if sflag.FlagIsDefined(clientFlags, "html-version") {
			flagExclusion = append(flagExclusion, "-html-version")
		}
		if sflag.FlagIsDefined(clientFlags, "html-health") {
			flagExclusion = append(flagExclusion, "-html-health")
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

func (c *client) startConnection(customDNS string) {
	wsURL, wErr := conf.FormatToWS(c.serverURL)
	if wErr != nil {
		c.Logger.Errorf("Failed to convert %s to WebSocket URL: %v", c.serverURL.String(), wErr)
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, rErr := conf.CustomResolver(customDNS, c.serverURL.Hostname())
		if rErr != nil {
			c.Logger.Errorf("Failed to resolve host %s: %v", c.serverURL.Hostname(), rErr)
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), c.serverURL.Hostname(), ip, 1)
		c.Logger.Debugf("Connecting to %s, resolved to IP: %s", wsURL, ip)
	}

	if wsURL.Scheme == "wss" {
		c.wsConfig.TLSClientConfig.InsecureSkipVerify = true
	}

	wsConn, _, cErr := c.wsConfig.DialContext(context.Background(), wsURLStr, c.httpHeaders)
	if cErr != nil {
		c.Logger.Errorf("Can't connect to Server address: %s", cErr)
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

	session.sshConn, newChan, reqChan, connErr = ssh.NewClientConn(netConn, session.wsConn.RemoteAddr().String(), c.sshConfig)
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
		case "sftp":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleSFTPChannel(nc)
		case "shell":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleShellChannel(nc)
		case "exec":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			go s.handleExecChannel(nc)
		case "init-size":
			s.Logger.Debugf("%sOpening \"%s\" channel", s.logID, nc.ChannelType())
			// Blocking here to ensure is serviced before another channel is opened
			s.handleInitSizeChannel(nc)
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

	// Create a net.Conn from the SSH channel
	socksConn := sconn.SSHChannelToNetConn(socksChan)
	defer func() { _ = socksConn.Close() }()

	// Set up configuration for the SOCKS5 server
	socksConf := &socks5.Config{
		// Disable logging
		Logger: slog.NewDummyLog(),
	}

	// Create a new SOCKS5 server
	server, err := socks5.New(socksConf)
	if err != nil {
		s.Logger.Errorf("%sFailed to create SOCKS5 server: %v", s.logID, err)
		return
	}

	// Serve the connection
	s.Logger.Debugf("%sStarting SOCKS5 server on connection", s.logID)
	if sErr := server.ServeConn(socksConn); sErr != nil {
		// Logging Errors as Debug as most of them are:
		// - Failed to handle request: EOF
		// - read: connection reset by peer
		s.Logger.Debugf("%sError in SOCKS5 server: %v", s.logID, sErr)
	}

	s.Logger.Debugf("%sSOCKS5 server connection closed", s.logID)
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

func (s *Session) handleInitSizeChannel(nc ssh.NewChannel) {
	channel, requests, err := nc.Accept()
	if err != nil {
		s.Logger.Errorf("Failed to accept channel - %v", err)
		return
	}
	defer func() {
		_ = channel.Close()
		s.Logger.Debugf("%sClosing INIT-SIZE channel", s.logID)
	}()
	payload := nc.ExtraData()
	go ssh.DiscardRequests(requests)
	s.Logger.Debugf("SSH Effective \"req-pty\" size as \"init-size\" payload: %v", payload)
	if len(payload) > 0 {
		var winSize conf.TermDimensions
		if jErr := json.Unmarshal(payload, &winSize); jErr != nil {
			s.Logger.Errorf("Failed to unmarshal terminal size payload: %v", jErr)
		}
		s.setInitTermSize(winSize)
	}
}
