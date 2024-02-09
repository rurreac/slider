package client

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"slider/pkg/sconn"
	"slider/pkg/slog"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type client struct {
	*slog.Logger
	serverAddr     string
	timeout        time.Duration
	wsConfig       *websocket.Dialer
	httpHeaders    http.Header
	sshConfig      *ssh.ClientConfig
	sshSession     *ssh.Session
	sshChannel     ssh.Channel
	interpreter    Interpreter
	reqConnChannel <-chan *ssh.Request
	debug          bool
}

func NewClient(args []string) {
	c := client{
		Logger: slog.NewLogger("Client"),
		interpreter: Interpreter{
			size: sconn.TermSize{},
		},
	}

	f := flag.NewFlagSet("Client", flag.ContinueOnError)
	f.BoolVar(&c.debug, "debug", false, "Verbose logging.")
	f.DurationVar(&c.timeout, "timeout", 60*time.Second, "Set global handshake timeout in seconds.")
	_ = f.Parse(args)

	if c.debug {
		c.Logger.WithDebug()
	}

	args = f.Args()
	c.serverAddr = args[0]

	c.wsConfig = &websocket.Dialer{
		NetDial:          nil,
		HandshakeTimeout: c.timeout,
		Subprotocols:     nil,
		// Use Default Buffer Size
		ReadBufferSize:  0,
		WriteBufferSize: 0,
	}

	// TODO: Provide Key authentication to the server if requested with flag otherwise fallback insecure
	c.sshConfig = &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-slider-client",
		Timeout:         c.timeout,
	}

	// TODO: Check the use of extra headers for added functionality
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism
	c.httpHeaders = http.Header{}

	wsConn, _, err := c.wsConfig.DialContext(context.Background(), fmt.Sprintf("ws://%s", c.serverAddr), c.httpHeaders)
	if err != nil {
		c.Fatalf("Can't connect to Server address: %s", err)
		return
	}
	/*
		TODO: Reverse Shell / SOCKS5 tunnel or both
	*/
	netConn := sconn.WsConnToNetConn(wsConn)
	// c.NewSSHClient(netConn)

	var sshClientConn ssh.Conn
	var newChan <-chan ssh.NewChannel
	var newCliErr error
	sshClientConn, newChan, c.reqConnChannel, newCliErr = ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
	if newCliErr != nil {
		c.Fatalf("%s\n", newCliErr)
		return
	}
	defer func() { _ = sshClientConn.Close() }()
	c.Debugf("Session %v\n", sshClientConn.SessionID())

	// Request Terminal Size from Server
	ok, termSizeBytes, termErr := sshClientConn.SendRequest("window-size", true, nil)
	if termErr != nil {
		c.Errorf("%s", termErr)
	}
	c.Debugf("Sent Request \"window-size\", received: \"%v\" from server with Payload: %s\n", ok, termSizeBytes)
	if unMarshalErr := json.Unmarshal(termSizeBytes, &c.interpreter.size); unMarshalErr != nil {
		c.Fatalf("%s", unMarshalErr)
	}

	sshClient := ssh.NewClient(sshClientConn, newChan, c.reqConnChannel)
	defer func() { _ = sshClient.Close() }()
	c.sshSession, err = sshClient.NewSession()
	if err != nil {
		c.Errorf("%s", err)
	}
	defer func() { _ = c.sshSession.Close() }()

	if err = c.ReverseShell(); err != nil {
		c.Errorf("%s", err)
	}
}
