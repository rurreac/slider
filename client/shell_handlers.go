package client

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"sync"

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

	cmd := exec.Command(s.interpreter.Shell)
	cmd.Env = append(os.Environ(), envVars...)

	if s.interpreter.PtyOn {
		s.Logger.Debugf("Running SHELL on PTY")
		cols := s.initTermSize.Width
		rows := s.initTermSize.Height
		// cols or rows should never be 0, if this happens, ConPTY will crash.
		if cols == 0 {
			cols = conf.DefaultTerminalWidth
		}
		if rows == 0 {
			rows = conf.DefaultTerminalHeight
		}

		ptyF, sErr := interpreter.StartPty(cmd, cols, rows)
		if sErr != nil {
			s.Logger.ErrorWith("Failed to start PTY", slog.F("err", sErr))
			_ = sshChan.Close()
			return
		}

		// Handle window changes
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := ptyF.Resize(cols, rows); sErr != nil {
					s.Logger.ErrorWith("Failed to set window size",
						slog.F("session_id", s.sessionID),
						slog.F("err", sErr))
				}
			}
		}()

		// Use a channel to signal when PTY process exits
		ptyDone := make(chan struct{})

		// Wait for process in background and close PTY to break the data pipe
		go func() {
			waitErr := ptyF.Wait()
			if waitErr != nil {
				s.Logger.DebugWith("Shell process exited with error",
					slog.F("session_id", s.sessionID),
					slog.F("err", waitErr))
			} else {
				s.Logger.DebugWith("Shell process exited normally", slog.F("session_id", s.sessionID))
			}
			_ = ptyF.Close()
			close(ptyDone)
		}()

		var wg sync.WaitGroup
		wg.Add(2)

		// Copy from PTY to SSH channel
		go func() {
			defer wg.Done()
			_, copyErr := io.Copy(sshChan, ptyF)
			if copyErr != nil && copyErr != io.EOF {
				s.Logger.DebugWith("Error copying from PTY to SSH",
					slog.F("session_id", s.sessionID),
					slog.F("err", copyErr))
			}
			// When PTY output is done, send EOF to SSH channel
			_ = sshChan.CloseWrite()
		}()

		// Copy from SSH channel to PTY
		go func() {
			defer wg.Done()
			_, copyErr := io.Copy(ptyF, sshChan)
			if copyErr != nil && copyErr != io.EOF {
				s.Logger.DebugWith("Error copying from SSH to PTY",
					slog.F("session_id", s.sessionID),
					slog.F("err", copyErr))
			}
			// When PTY output is done, send EOF to SSH channel
			_ = sshChan.CloseWrite()
		}()

		wg.Wait()
		<-ptyDone // Ensure PTY cleanup is complete
		s.Logger.DebugWith("Shell I/O piping completed", slog.F("session_id", s.sessionID))
	} else {
		s.Logger.Debugf("Running SHELL on NON PTY")

		// Handle window-change events
		go func() {
			for range winChange {
			}
		}()

		// Windows non-PTY shell requires /qa flag
		if s.interpreter.System == "windows" {
			cmd.Args = append(cmd.Args, "/qa")
		}

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

		cmd.Stdin = sshChan

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
	cmd := exec.Command(s.interpreter.Shell, append(s.interpreter.CmdArgs, rcvCmd)...)

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
		s.Logger.Debugf("Running EXEC on PTY")
		cols := s.initTermSize.Width
		rows := s.initTermSize.Height
		if cols == 0 {
			cols = 80
		}
		if rows == 0 {
			rows = 24
		}

		ptyF, fErr := interpreter.StartPty(cmd, cols, rows)
		if fErr != nil {
			s.Logger.ErrorWith("Failed to start command",
				slog.F("session_id", s.sessionID),
				slog.F("err", fErr))
			return
		}

		// Handle window-change events
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := ptyF.Resize(cols, rows); sErr != nil {
					s.Logger.ErrorWith("Failed to update window size",
						slog.F("session_id", s.sessionID),
						slog.F("err", sErr))
				}
			}
		}()

		// Use a channel to signal when PTY process exits
		ptyDone := make(chan struct{})

		// Wait for process in background and close PTY to break the data pipe
		go func() {
			waitErr := ptyF.Wait()
			if waitErr != nil {
				s.Logger.DebugWith("Exec process exited with error",
					slog.F("session_id", s.sessionID),
					slog.F("err", waitErr))
			} else {
				s.Logger.DebugWith("Exec process exited normally", slog.F("session_id", s.sessionID))
			}
			_ = ptyF.Close()
			close(ptyDone)
		}()

		var wg sync.WaitGroup
		wg.Add(2)

		// Copy from PTY to SSH channel
		go func() {
			defer wg.Done()
			_, copyErr := io.Copy(sshChan, ptyF)
			if copyErr != nil && copyErr != io.EOF {
				s.Logger.DebugWith("Error copying from PTY to SSH",
					slog.F("session_id", s.sessionID),
					slog.F("err", copyErr))
			}
			// When PTY output is done, send EOF to SSH channel
			_ = sshChan.CloseWrite()
		}()

		// Copy from SSH channel to PTY
		go func() {
			defer wg.Done()
			_, copyErr := io.Copy(ptyF, sshChan)
			if copyErr != nil && copyErr != io.EOF {
				s.Logger.DebugWith("Error copying from SSH to PTY",
					slog.F("session_id", s.sessionID),
					slog.F("err", copyErr))
			}
		}()

		wg.Wait()
		<-ptyDone // Ensure PTY cleanup is complete
		s.Logger.DebugWith("Exec I/O piping completed", slog.F("session_id", s.sessionID))
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
