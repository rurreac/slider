package session

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/interpreter"
	"slider/pkg/slog"
	"slider/pkg/types"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// HandleExec processes an exec channel for ANY role
func (s *BidirectionalSession) HandleExec(nc ssh.NewChannel) error {
	s.logger.DebugWith("Handling exec channel",
		slog.F("session_id", s.sessionID),
		slog.F("role", s.role.String()))

	// Accept channel
	sshChan, requests, err := nc.Accept()
	if err != nil {
		s.logger.ErrorWith("Failed to accept exec channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}
	defer func() { _ = sshChan.Close() }()

	s.AddChannel(sshChan)

	// Create channels for requests
	winChange := make(chan []byte, 10)
	envChange := make(chan []byte, 10)

	// Handle SSH requests
	go s.handleSSHRequests(requests, winChange, envChange)

	// Collect environment variables
	var envVars []string
	var useAltShell bool
	var execWithPty bool // Whether caller requested PTY for this exec
	for envBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(envBytes, &kv)
		if kv.Key == conf.SliderCloserEnvVar && kv.Value == "true" {
			break
		} else {
			s.logger.DebugWith("Processing environment variable",
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
			// Do not save Slider environment variables
			if kv.Key == conf.SliderAltShellEnvVar && kv.Value == "true" {
				useAltShell = true
				continue
			}
			if kv.Key == conf.SliderExecPtyEnvVar && kv.Value == "true" {
				execWithPty = true
				continue
			}
			// Save the rest of the environment variables
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
		}
	}

	var cCmd types.CustomCmd
	var path, command, rcvCmd, cmdSeparator string
	cmdSeparator = s.localInterpreter.ShellSeparator
	if useAltShell {
		cmdSeparator = s.localInterpreter.AltShellSeparator
	}
	// Extract command from ExtraData

	// Extract as SSH wire format - command from external ssh connection
	// First 4 elements are 3 null bytes plus the size of the payload
	rcvCmdBytes := nc.ExtraData()[4:]
	rcvCmd = string(rcvCmdBytes)
	// Try CustomCmd format first internal command from Session
	if jErr := json.Unmarshal(rcvCmdBytes, &cCmd); jErr == nil {
		path = cCmd.Path
		command = cCmd.Command
		s.logger.DebugWith("CustomCmd format",
			slog.F("session_id", s.sessionID),
			slog.F("path", path),
			slog.F("command", command))
		rcvCmd = "cd " + path + " " + cmdSeparator + " " + command
	}
	s.logger.DebugWith("Channel ExtraData",
		slog.F("session_id", s.sessionID),
		slog.F("extra_data", rcvCmdBytes))

	// Drain environment variable channel in background
	go func() {
		for range envChange {
		}
	}()

	var exitCode int
	// Execute command:
	s.logger.DebugWith("Command request",
		slog.F("session_id", s.sessionID),
		slog.F("cmd", rcvCmd),
		slog.F("exec_with_pty", execWithPty),
		slog.F("pty_on", s.localInterpreter.PtyOn),
		slog.F("system", s.localInterpreter.System))

	if execWithPty && s.localInterpreter.PtyOn {
		exitCode, err = s.executeCommandWithPty(rcvCmd, sshChan, winChange, envVars, useAltShell)
	} else {
		// Drain window change channel if not using PTY
		go func() {
			for range winChange {
			}
		}()
		exitCode, err = s.executeCommandWithoutPty(rcvCmd, sshChan, envVars, useAltShell)
	}

	// Send exit status
	exitPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(exitPayload, uint32(exitCode))
	_, _ = sshChan.SendRequest("exit-status", false, exitPayload)

	return err
}

// executeCommandWithPty runs command with PTY
func (s *BidirectionalSession) executeCommandWithPty(
	command string,
	channel ssh.Channel,
	winChange <-chan []byte,
	envVars []string,
	useAltShell bool,
) (int, error) {
	// Get the local execution parameters
	var shell string
	var execArgs []string
	if s.localInterpreter != nil && s.localInterpreter.Shell != "" {
		shell = s.localInterpreter.Shell
		execArgs = s.localInterpreter.ShellExecArgs
		if useAltShell && s.localInterpreter.AltShell != "" {
			shell = s.localInterpreter.AltShell
			execArgs = s.localInterpreter.AltShellExecArgs
		}
	} else {
		return 255, fmt.Errorf("local interpreter not found")
	}

	s.logger.DebugWith("Running EXEC on PTY",
		slog.F("session_id", s.sessionID),
		slog.F("cmd", command))

	cmd := exec.Command(shell, append(execArgs, command)...)
	cmd.Env = append(os.Environ(), envVars...)

	// Get terminal size
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
		s.logger.ErrorWith("Failed to start command",
			slog.F("session_id", s.sessionID),
			slog.F("err", fErr))
		return 1, fErr
	}

	// Handle window-change events
	go func() {
		for sizeBytes := range winChange {
			cols, rows := instance.ParseSizePayload(sizeBytes)
			if sErr := ptyF.Resize(cols, rows); sErr != nil {
				s.logger.ErrorWith("Failed to update window size",
					slog.F("session_id", s.sessionID),
					slog.F("err", sErr))
			}
		}
	}()

	// Use a channel to signal when PTY process exits
	ptyDone := make(chan struct{})

	// Wait for process in background
	go func() {
		waitErr := ptyF.Wait()
		if waitErr != nil {
			s.logger.DebugWith("Exec process exited with error",
				slog.F("session_id", s.sessionID),
				slog.F("err", waitErr))
		} else {
			s.logger.DebugWith("Exec process exited normally",
				slog.F("session_id", s.sessionID))
		}
		_ = ptyF.Close()
		close(ptyDone)
	}()

	var wg sync.WaitGroup

	// Copy from PTY to SSH channel and wait, the channel will be closed
	// on the other end when the exit-status request is received
	wg.Go(func() {
		_, copyErr := io.Copy(channel, ptyF)
		if copyErr != nil && copyErr != io.EOF {
			s.logger.DebugWith("Error copying from PTY to SSH",
				slog.F("session_id", s.sessionID),
				slog.F("err", copyErr))
		}
		_ = channel.CloseWrite()
	})

	// Copy from SSH channel to PTY
	go func() {
		_, copyErr := io.Copy(ptyF, channel)
		if copyErr != nil && copyErr != io.EOF {
			s.logger.DebugWith("Error copying from SSH to PTY",
				slog.F("session_id", s.sessionID),
				slog.F("err", copyErr))
		}
	}()

	wg.Wait()
	<-ptyDone

	s.logger.DebugWith("Exec I/O piping completed",
		slog.F("session_id", s.sessionID))

	// Get exit code
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}

	return exitCode, nil
}

// executeCommandWithoutPty runs command without PTY
func (s *BidirectionalSession) executeCommandWithoutPty(
	command string,
	channel ssh.Channel,
	envVars []string,
	useAltShell bool,
) (int, error) {
	// Get the local execution parameters
	var shell string
	var execArgs []string
	if s.localInterpreter != nil {
		shell = s.localInterpreter.Shell
		execArgs = s.localInterpreter.ShellExecArgs
		if useAltShell && s.localInterpreter.AltShell != "" {
			shell = s.localInterpreter.AltShell
			execArgs = s.localInterpreter.AltShellExecArgs
		}
	} else {
		return 0, fmt.Errorf("local interpreter not found")
	}

	s.logger.DebugWith("Running EXEC on NON PTY",
		slog.F("session_id", s.sessionID),
		slog.F("cmd", command))

	// Create a context with a 10-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, shell, append(execArgs, command)...)
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
		s.logger.ErrorWith("Failed to wait for command or timed out",
			slog.F("session_id", s.sessionID),
			slog.F("err", wErr))
		exitCode := 1
		if cmd.ProcessState != nil {
			exitCode = cmd.ProcessState.ExitCode()
		}
		return exitCode, wErr
	}

	s.logger.DebugWith("Non-PTY exec completed",
		slog.F("session_id", s.sessionID))

	return 0, nil
}
