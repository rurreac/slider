//go:build windows

package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slider/pkg/instance"
	"slider/pkg/slog"

	"github.com/UserExistsError/conpty"
	"golang.org/x/crypto/ssh"
)

func (s *Session) handleShellChannel(channel ssh.NewChannel) {
	sshChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.WithCaller().ErrorWith(
			"Failed to accept \"%s\" channel",
			nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()),
			slog.F("err", aErr),
		)
		return
	}
	defer func() {
		s.Logger.WithCaller().DebugWith("Closing channel", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()))
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
				s.Logger.WithCaller().DebugWith("Adding Environment variable", nil,
					slog.F("session_id", s.sessionID),
					slog.F("key", kv.Key),
					slog.F("value", kv.Value))
			}
		}

		s.Logger.WithCaller().Debugf("Running SHELL on PTY")
		cmd := exec.Command(s.interpreter.Shell)
		conPty, cErr := conpty.Start(
			s.interpreter.Shell,
			conpty.ConPtyDimensions(int(s.initTermSize.Width), int(s.initTermSize.Height)),
			conpty.ConPtyEnv(append(cmd.Environ(), envVars...)),
		)
		if cErr != nil {
			s.Logger.WithCaller().ErrorWith("Failed to start conpty", nil,
				slog.F("session_id", s.sessionID),
				slog.F("err", cErr))
			return
		}
		defer func() { _ = conPty.Close() }()

		// Handle window changes
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := conPty.Resize(int(cols), int(rows)); sErr != nil {
					s.Logger.WithCaller().WarnWith("Failed to update window size", nil,
						slog.F("session_id", s.sessionID),
						slog.F("err", sErr))
				}
			}
		}()

		go func() { _, _ = io.Copy(conPty, sshChan) }()
		go func() { _, _ = io.Copy(sshChan, conPty) }()

		if code, err := conPty.Wait(context.Background()); err != nil {
			s.Logger.WithCaller().ErrorWith("Failed to spawn conpty", nil,
				slog.F("session_id", s.sessionID),
				slog.F("exit_code", code),
				slog.F("err", err))
		}
	} else {
		// - You are here cause the System is likely Windows < 2018 and does not support ConPTY
		// - Command Prompt Buffer Size can be set running: `mode con:cols=X lines=Y`,
		//   unfortunately, there's no equivalent variable to set that up,
		//   so size won't be set or updated
		s.Logger.WithCaller().Debugf("Running SHELL on NON PTY")

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
				s.Logger.WithCaller().DebugWith("Adding Environment variable", nil,
					slog.F("session_id", s.sessionID),
					slog.F("key", kv.Key),
					slog.F("value", kv.Value))
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
			s.Logger.WithCaller().ErrorWith("Failed to start process", nil,
				slog.F("session_id", s.sessionID),
				slog.F("err", err))
			return
		}

		if err := cmd.Wait(); err != nil {
			s.Logger.WithCaller().ErrorWith("Command exited", nil,
				slog.F("session_id", s.sessionID),
				slog.F("err", err))
		}
	}

}

func (s *Session) handleExecChannel(channel ssh.NewChannel) {
	sshChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to accept channel", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()),
			slog.F("err", aErr))
		return
	}
	defer func() {
		s.Logger.WithCaller().DebugWith("Closing channel", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()))
		_ = sshChan.Close()
	}()

	winChange := make(chan []byte, 10)
	defer close(winChange)

	// This channel will be a blocker and closed by the server request
	envChange := make(chan []byte, 10)

	// The first 4 elements of Channel.Extradata() are 3 null bytes plus the size of the payload
	// The rest of the payload is the command to be executed
	s.Logger.WithCaller().DebugWith("Channel ExtraData", nil,
		slog.F("session_id", s.sessionID),
		slog.F("extra_data", channel.ExtraData()))

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
			s.Logger.WithCaller().DebugWith("Adding Environment variable", nil,
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
		}
	}

	s.Logger.WithCaller().DebugWith("Running EXEC on NON PTY", nil,
		slog.F("session_id", s.sessionID))

	cmd := &exec.Cmd{
		Path:   s.interpreter.Shell,
		Args:   append(s.interpreter.CmdArgs, rcvCmd),
		Env:    append(os.Environ(), envVars...),
		Stdout: sshChan,
		Stderr: sshChan,
	}

	if err := cmd.Start(); err != nil {
		s.Logger.WithCaller().ErrorWith("Failed to start command", nil,
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return
	}

	if err := cmd.Wait(); err != nil {
		s.Logger.WithCaller().ErrorWith("Command exited", nil,
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
	}
}
