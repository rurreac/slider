package session

import (
	"encoding/binary"
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

// HandleShell processes a shell channel for ANY role
func (s *BidirectionalSession) HandleShell(nc ssh.NewChannel) error {
	s.logger.DebugWith("Handling shell channel",
		slog.F("session_id", s.sessionID),
		slog.F("role", s.role.String()))

	// Accept channel
	sshChan, requests, err := nc.Accept()
	if err != nil {
		s.logger.ErrorWith("Failed to accept shell channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return fmt.Errorf("accept channel: %w", err)
	}
	defer func() {
		s.logger.DebugWith("Closing shell channel",
			slog.F("session_id", s.sessionID))
		_ = sshChan.Close()
	}()

	// Register channel
	s.AddChannel(sshChan)

	// Create channels for requests
	winChange := make(chan []byte, 10)
	envChange := make(chan []byte, 10)

	// Handle SSH requests (PTY, window-change, env)
	go s.handleSSHRequests(requests, winChange, envChange)

	// Collect environment variables
	var envVars []string
	var useAltShell bool
	for envBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(envBytes, &kv)
		// Break the loop when the closer environment variable is set
		if kv.Key == conf.SliderCloserEnvVar && kv.Value == "true" {
			break
		} else {
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			if kv.Key == conf.SliderAltShellEnvVar && kv.Value == "true" {
				useAltShell = true
			}
			s.logger.DebugWith("Received environment variable",
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
		}
	}
	// Drain environment variable channel in background
	go func() {
		for range envChange {
		}
	}()

	// Execute shell based on PTY availability of the peer
	var exitCode int
	var eErr error
	if s.peerBaseInfo.PtyOn {
		exitCode, eErr = s.executeShellWithPty(sshChan, winChange, envVars, useAltShell)
	} else {
		// Drain window change channel if not using PTY
		go func() {
			for range winChange {
			}
		}()

		exitCode, eErr = s.executeShellWithoutPty(sshChan, envVars, useAltShell)
	}

	// Send exit status
	exitPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(exitPayload, uint32(exitCode))
	_, _ = sshChan.SendRequest("exit-status", false, exitPayload)

	return eErr

}

// executeShellWithPty runs an interactive shell with PTY
func (s *BidirectionalSession) executeShellWithPty(
	channel ssh.Channel,
	winChange <-chan []byte,
	envVars []string,
	useAltShell bool,
) (int, error) {
	// Get the local execution parameters
	var shell string
	var args []string
	if s.localInterpreter != nil && s.localInterpreter.Shell != "" {
		shell = s.localInterpreter.Shell
		args = s.localInterpreter.ShellArgs
		if useAltShell && s.localInterpreter.AltShell != "" {
			shell = s.localInterpreter.AltShell
			args = s.localInterpreter.AltShellArgs
		}
	} else {
		return 255, fmt.Errorf("local interpreter not found")
	}

	s.logger.DebugWith("Running SHELL on PTY",
		slog.F("session_id", s.sessionID),
		slog.F("shell", shell),
		slog.F("use_alt", useAltShell))

	cmd := exec.Command(shell, args...)
	cmd.Env = append(os.Environ(), envVars...)

	// Get terminal size
	cols := s.initTermSize.Width
	rows := s.initTermSize.Height
	if cols == 0 {
		cols = conf.DefaultTerminalWidth
	}
	if rows == 0 {
		rows = conf.DefaultTerminalHeight
	}

	// Start with PTY
	ptyF, err := interpreter.StartPty(cmd, cols, rows)
	if err != nil {
		s.logger.ErrorWith("Failed to start PTY",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return 1, fmt.Errorf("start pty: %w", err)
	}

	// Handle window resize
	go func() {
		for sizeBytes := range winChange {
			cols, rows := instance.ParseSizePayload(sizeBytes)
			if sErr := ptyF.Resize(cols, rows); sErr != nil {
				s.logger.ErrorWith("Failed to set window size",
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
			s.logger.DebugWith("Shell process exited with error",
				slog.F("session_id", s.sessionID),
				slog.F("err", waitErr))
		} else {
			s.logger.DebugWith("Shell process exited normally",
				slog.F("session_id", s.sessionID))
		}
		_ = ptyF.Close()
		close(ptyDone)
	}()

	var wg sync.WaitGroup
	wg.Add(1) // Only wait for Output copy

	// Copy from PTY to SSH channel
	go func() {
		defer wg.Done()
		_, copyErr := io.Copy(channel, ptyF)
		if copyErr != nil && copyErr != io.EOF {
			s.logger.DebugWith("Error copying from PTY to SSH",
				slog.F("session_id", s.sessionID),
				slog.F("err", copyErr))
		}
		// When PTY output is done, send EOF to SSH channel
		_ = channel.CloseWrite()
	}()

	// Copy from SSH channel to PTY (don't wait for this)
	go func() {
		_, copyErr := io.Copy(ptyF, channel)
		if copyErr != nil && copyErr != io.EOF {
			s.logger.DebugWith("Error copying from SSH to PTY",
				slog.F("session_id", s.sessionID),
				slog.F("err", copyErr))
		}
	}()

	wg.Wait()
	<-ptyDone // Ensure PTY cleanup is complete
	s.logger.DebugWith("Shell I/O piping completed",
		slog.F("session_id", s.sessionID))

	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	return exitCode, nil
}

// executeShellWithoutPty runs a non-interactive shell
func (s *BidirectionalSession) executeShellWithoutPty(
	channel ssh.Channel,
	envVars []string,
	useAltShell bool,
) (int, error) {
	// Get the local execution parameters
	var shell string
	var args []string
	if s.localInterpreter != nil {
		shell = s.localInterpreter.Shell
		args = s.localInterpreter.ShellArgs
		if useAltShell && s.localInterpreter.AltShell != "" {
			shell = s.localInterpreter.AltShell
			args = s.localInterpreter.AltShellArgs
		}
	} else {
		return 255, fmt.Errorf("local interpreter not found")
	}

	s.logger.DebugWith("Running SHELL on NON PTY",
		slog.F("session_id", s.sessionID),
		slog.F("shell", shell),
		slog.F("use_alt", useAltShell))

	cmd := exec.Command(shell, args...)
	cmd.Env = append(os.Environ(), envVars...)

	outRC, oErr := cmd.StdoutPipe()
	if oErr != nil {
		s.logger.ErrorWith("Failed to get stdout pipe",
			slog.F("session_id", s.sessionID),
			slog.F("err", oErr))
		return 1, oErr
	}

	errRC, eErr := cmd.StderrPipe()
	if eErr != nil {
		s.logger.ErrorWith("Failed to get stderr pipe",
			slog.F("session_id", s.sessionID),
			slog.F("err", eErr))
		return 1, eErr
	}

	cmd.Stdin = channel
	if runErr := cmd.Start(); runErr != nil {
		s.logger.ErrorWith("Failed to execute command",
			slog.F("session_id", s.sessionID),
			slog.F("err", runErr))
		return 1, runErr
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, outRC)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(channel, errRC)
	}()

	wErr := cmd.Wait()
	wg.Wait()
	if wErr != nil {
		s.logger.ErrorWith("Failed to wait for command",
			slog.F("session_id", s.sessionID),
			slog.F("err", wErr))
		exitCode := 1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		return exitCode, wErr
	}

	s.logger.DebugWith("Non-PTY shell completed",
		slog.F("session_id", s.sessionID))
	return 0, nil
}
