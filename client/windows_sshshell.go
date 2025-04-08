//go:build windows

package client

import (
	"context"
	"fmt"
	"github.com/UserExistsError/conpty"
	"golang.org/x/crypto/ssh"
	"io"
	"os/exec"
	"slider/pkg/instance"
)

func (s *Session) handleShellChannel(channel ssh.NewChannel) {
	sshChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.Errorf(
			"%sFailed to accept \"%s\" channel\n%v",
			s.logID,
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() {
		s.Logger.Debugf("%sClosing SSH channel", s.logID)
		_ = sshChan.Close()
	}()

	winChange := make(chan []byte, 10)
	defer close(winChange)

	// This channel will be a blocker and closed by the server request
	envChange := make(chan []byte, 10)

	go s.handleSSHRequests(requests, winChange, envChange)

	if s.interpreter.PtyOn {
		// Handle environment variable events
		var envVars []string
		for sizeBytes := range envChange {
			var kv struct{ Key, Value string }
			_ = ssh.Unmarshal(sizeBytes, &kv)
			// Close the channel when the SLIDER_ENV environment variable is set,
			// so the command can be executed after all environment variables are set.
			if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
				close(envChange)
			} else {
				envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
				s.Logger.Debugf("Adding Environment variable: %s=\"%s\"\n", kv.Key, kv.Value)
			}
		}

		s.Logger.Debugf("Running SHELL on PTY")
		cmd := exec.Command(s.interpreter.Shell)
		conPty, cErr := conpty.Start(
			s.interpreter.Shell,
			conpty.ConPtyDimensions(int(s.initTermSize.Width), int(s.initTermSize.Height)),
			conpty.ConPtyEnv(append(cmd.Environ(), envVars...)),
		)
		if cErr != nil {
			s.Logger.Errorf("Failed to start conpty - %v", cErr)
			return
		}
		defer func() { _ = conPty.Close() }()

		// Handle window changes
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := conPty.Resize(int(cols), int(rows)); sErr != nil {
					s.Logger.Warnf("Failed to update window size - %v", sErr)
				}
			}
		}()

		go func() { _, _ = io.Copy(conPty, sshChan) }()
		go func() { _, _ = io.Copy(sshChan, conPty) }()

		if code, err := conPty.Wait(context.Background()); err != nil {
			s.Logger.Errorf("Failed to spawn conpty with exit code %d", code)
		}
	} else {
		// - You are here cause the System is likely Windows < 2018 and does not support ConPTY
		// - Command Prompt Buffer Size can be set running: `mode con:cols=X lines=Y`,
		//   unfortunately there's no equivalent variable to set that up,
		//   so size won't be set or updated
		s.Logger.Debugf("Running SHELL on NON PTY")
		pr, pw := io.Pipe()
		cmd := exec.Command(s.interpreter.Shell, s.interpreter.ShellArgs...) //nolint:gosec

		// Handle environment variable events
		var envVars []string
		for sizeBytes := range envChange {
			var kv struct{ Key, Value string }
			_ = ssh.Unmarshal(sizeBytes, &kv)
			// Close the channel when the SLIDER_ENV environment variable is set,
			// so the command can be executed after all environment variables are set.
			if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
				close(envChange)
			} else {
				envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
				s.Logger.Debugf("Adding Environment variable: %s=\"%s\"\n", kv.Key, kv.Value)
			}
		}

		cmd.Env = append(cmd.Environ(), envVars...)
		cmd.Stdin = sshChan
		cmd.Stdout = pw
		cmd.Stderr = pw

		// Discard window-change events
		go func() {
			for range envChange {
			}
		}()

		go func() { _, _ = io.Copy(sshChan, pr) }()

		if runErr := cmd.Run(); runErr != nil {
			s.Logger.Errorf("%v", runErr)
		}
	}

}

func (s *Session) handleExecChannel(channel ssh.NewChannel) {
	sshChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.Errorf(
			"%sFailed to accept \"%s\" channel\n%v",
			s.logID,
			channel.ChannelType(),
			aErr,
		)
		return
	}
	defer func() {
		s.Logger.Debugf("%sClosing EXEC channel", s.logID)
		_ = sshChan.Close()
	}()

	winChange := make(chan []byte, 10)
	defer close(winChange)

	// This channel will be a blocker and closed by the server request
	envChange := make(chan []byte, 10)

	// First 4 elements of Channel.Extradata() are 3 null bytes plus the size of the payload
	// The rest of the payload is the command to be executed
	s.Logger.Debugf("ExtraData: %v", channel.ExtraData())

	rcvCmd := string(channel.ExtraData()[4:])

	go s.handleSSHRequests(requests, winChange, envChange)

	// Handle environment variable events
	var envVars []string
	for sizeBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(sizeBytes, &kv)
		// Close the channel when the SLIDER_ENV environment variable is set,
		// so the command can be executed after all environment variables are set.
		if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
			close(envChange)
		} else {
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			s.Logger.Debugf("Adding Environment variable: %s=\"%s\"\n", kv.Key, kv.Value)
		}
	}

	s.Logger.Debugf("Running EXEC on NON PTY")
	cmd := exec.Command(s.interpreter.Shell, append(s.interpreter.CmdArgs, rcvCmd)...) //nolint:gosec
	cmd.Env = append(cmd.Environ(), envVars...)

	outRC, oErr := cmd.StdoutPipe()
	if oErr != nil {
		s.Logger.Errorf("Failed to get stdout pipe - %v", oErr)
		return
	}
	errRC, eErr := cmd.StderrPipe()
	if eErr != nil {
		s.Logger.Errorf("Failed to get stderr pipe - %v", eErr)
		return
	}

	if runErr := cmd.Start(); runErr != nil {
		s.Logger.Errorf("Failed to execute command - %v", runErr)
		return
	}

	// Discard window-change events
	go func() {
		for range envChange {
		}
	}()

	go func() { _, _ = io.Copy(sshChan, outRC) }()
	go func() { _, _ = io.Copy(sshChan, errRC) }()

	if wErr := cmd.Wait(); wErr != nil {
		s.Logger.Errorf("Failed to wait for command - %v", wErr)
	}

}
