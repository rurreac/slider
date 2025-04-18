//go:build windows

package client

import (
	"context"
	"fmt"
	"github.com/UserExistsError/conpty"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
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
		s.Logger.Debugf(s.logID+"Closing \"%s\" channel", channel.ChannelType())
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
		//   unfortunately, there's no equivalent variable to set that up,
		//   so size won't be set or updated
		s.Logger.Debugf("Running SHELL on NON PTY")

		// Discard window-change events
		go func() {
			for range winChange {
			}
		}()

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

		cmd := &exec.Cmd{
			Path:   s.interpreter.Shell,
			Args:   []string{"/qa"},
			Env:    envVars,
			Stdin:  sshChan,
			Stdout: sshChan,
			Stderr: sshChan,
		}

		if err := cmd.Start(); err != nil {
			s.Logger.Fatalf(s.logID+"Failed to start process: %v", err)
			return
		}

		if err := cmd.Wait(); err != nil {
			s.Logger.Fatalf(s.logID+"Command exited: %v", err)
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

	// The first 4 elements of Channel.Extradata() are 3 null bytes plus the size of the payload
	// The rest of the payload is the command to be executed
	s.Logger.Debugf("ExtraData: %v", channel.ExtraData())

	rcvCmd := string(channel.ExtraData()[4:])

	go s.handleSSHRequests(requests, winChange, envChange)

	// Discard window-change events
	go func() {
		for range winChange {
		}
	}()

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

	cmd := &exec.Cmd{
		Path:   s.interpreter.Shell,
		Args:   append(s.interpreter.CmdArgs, rcvCmd),
		Env:    append(os.Environ(), envVars...),
		Stdout: sshChan,
		Stderr: sshChan,
	}

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start process: %v", err)
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("Command exited: %v", err)
	}
}
