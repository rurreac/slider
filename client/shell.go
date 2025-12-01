//go:build !windows

package client

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"slider/pkg/instance"
	"slider/pkg/sio"
	"slider/pkg/slog"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

func (s *Session) handleShellChannel(channel ssh.NewChannel) {
	sshChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.ErrorWith("Failed to accept channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()),
			slog.F("err", aErr))
		return
	}
	defer func() {
		s.Logger.DebugWith("Closing channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()))
		_ = sshChan.Close()
	}()

	winChange := make(chan []byte, 10)
	defer close(winChange)

	// This channel will be a blocker and closed by the server request
	envChange := make(chan []byte, 10)

	cmd := exec.Command(s.interpreter.Shell) //nolint:gosec

	go s.handleSSHRequests(requests, winChange, envChange)

	// Handle environment variable events
	var envVars []string
	for envBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(envBytes, &kv)
		// Close the channel when the SLIDER_ENV environment variable is set,
		// so the command can be executed after all environment variables are set.
		if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
			close(envChange)
		} else {
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			s.Logger.DebugWith("Adding Environment variable",
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
		}
	}
	cmd.Env = append(os.Environ(), envVars...)

	if s.interpreter.PtyOn {
		s.Logger.Debugf("Running SHELL on PTY")
		ptyF, _ := pty.StartWithSize(
			cmd,
			&pty.Winsize{
				Rows: uint16(s.initTermSize.Height),
				Cols: uint16(s.initTermSize.Width)},
		)
		defer func() { _ = ptyF.Close() }()

		// Handle window changes
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := pty.Setsize(ptyF, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); sErr != nil {
					s.Logger.ErrorWith("Failed to set window size",
						slog.F("session_id", s.sessionID),
						slog.F("err", sErr))
				}
			}
		}()

		_, _ = sio.PipeWithCancel(ptyF, sshChan)

	} else {
		s.Logger.Debugf("Running SHELL on NON PTY")

		// Handle window-change events
		go func() {
			for range winChange {
			}
		}()

		outRC, oErr := cmd.StdoutPipe()
		if oErr != nil {
			s.Logger.ErrorWith("Failed to get stdout pipe",
				slog.F("session_id", s.sessionID),
				slog.F("err", oErr))
			return
		}
		errRC, eErr := cmd.StderrPipe()
		if eErr != nil {
			s.Logger.ErrorWith("Failed to get stderr pipe",
				slog.F("session_id", s.sessionID),
				slog.F("err", eErr))
			return
		}

		if runErr := cmd.Start(); runErr != nil {
			s.Logger.ErrorWith("Failed to execute command",
				slog.F("session_id", s.sessionID),
				slog.F("err", runErr))
			return
		}

		go func() { _, _ = io.Copy(sshChan, outRC) }()
		go func() { _, _ = io.Copy(sshChan, errRC) }()

		if wErr := cmd.Wait(); wErr != nil {
			s.Logger.ErrorWith("Failed to wait for command",
				slog.F("session_id", s.sessionID),
				slog.F("err", wErr))
		}

	}
}

func (s *Session) handleExecChannel(channel ssh.NewChannel) {
	sshChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.ErrorWith("Failed to accept channel",
			slog.F("session_id", s.sessionID),
			slog.F("channel_type", channel.ChannelType()),
			slog.F("err", aErr))
		return
	}
	defer func() { _ = sshChan.Close() }()

	winChange := make(chan []byte, 10)
	defer close(winChange)

	// This channel will be a blocker and closed by the server request
	envChange := make(chan []byte, 10)

	// First 4 elements of Channel.Extradata() are 3 null bytes plus the size of the payload
	// The rest of the payload is the command to be executed
	s.Logger.DebugWith("Channel ExtraData",
		slog.F("session_id", s.sessionID),
		slog.F("extra_data", channel.ExtraData()))

	rcvCmd := string(channel.ExtraData()[4:])
	cmd := exec.Command(s.interpreter.Shell, append(s.interpreter.CmdArgs, rcvCmd)...) //nolint:gosec

	go s.handleSSHRequests(requests, winChange, envChange)

	// Handle environment variable events
	var envVars []string
	for envBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(envBytes, &kv)
		// Close the channel when the SLIDER_ENV environment variable is set,
		// so the command can be executed after all environment variables are set.
		if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
			close(envChange)
		} else {
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			s.Logger.DebugWith("Adding Environment variable",
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
		}
	}
	cmd.Env = append(cmd.Environ(), envVars...)

	if s.interpreter.PtyOn {
		s.Logger.Debugf("Running EXEC on PTY")
		ptyF, fErr := pty.Start(cmd)
		if fErr != nil {
			s.Logger.ErrorWith("Failed to start command",
				slog.F("session_id", s.sessionID),
				slog.F("err", fErr))
			return
		}
		defer func() { _ = ptyF.Close() }()
		if sErr := pty.Setsize(ptyF, &pty.Winsize{
			Rows: uint16(s.initTermSize.Height),
			Cols: uint16(s.initTermSize.Width)}); sErr != nil {
			s.Logger.ErrorWith("Failed to set window size",
				slog.F("session_id", s.sessionID),
				slog.F("err", sErr))
		}

		// Handle window-change events
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := pty.Setsize(ptyF, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); sErr != nil {
					s.Logger.ErrorWith("Failed to update window size",
						slog.F("session_id", s.sessionID),
						slog.F("err", sErr))
				}
			}
		}()

		_, _ = sio.PipeWithCancel(ptyF, sshChan)

	} else {
		s.Logger.Debugf("Running EXEC on NON PTY")
		// Handle window-change events
		go func() {
			for range winChange {
			}
		}()

		outRC, oErr := cmd.StdoutPipe()
		if oErr != nil {
			s.Logger.ErrorWith("Failed to get stdout pipe",
				slog.F("session_id", s.sessionID),
				slog.F("err", oErr))
			return
		}
		errRC, eErr := cmd.StderrPipe()
		if eErr != nil {
			s.Logger.ErrorWith("Failed to get stderr pipe",
				slog.F("session_id", s.sessionID),
				slog.F("err", eErr))
			return
		}

		if runErr := cmd.Start(); runErr != nil {
			s.Logger.ErrorWith("Failed to execute command",
				slog.F("session_id", s.sessionID),
				slog.F("err", runErr))
			return
		}

		go func() { _, _ = io.Copy(sshChan, outRC) }()
		go func() { _, _ = io.Copy(sshChan, errRC) }()

		if wErr := cmd.Wait(); wErr != nil {
			s.Logger.ErrorWith("Failed to wait for command",
				slog.F("session_id", s.sessionID),
				slog.F("err", wErr))
		}
	}

}
