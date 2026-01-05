package session

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

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// ========================================
// Shell Handler
// ========================================

// HandleShell processes a shell channel for ANY role.
// This single method replaces:
// - client/shell_handlers.go:handleShellChannel()
// - server/remote/handlers.go:HandleShell()
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
	defer close(winChange)
	envChange := make(chan []byte, 10)

	// Handle SSH requests (PTY, window-change, env)
	go s.handleSSHRequests(requests, winChange, envChange)

	// Collect environment variables
	var envVars []string
	for envBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(envBytes, &kv)
		// Close the channel when the SLIDER_ENV environment variable is set
		if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
			close(envChange)
		} else {
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			s.logger.DebugWith("Adding environment variable",
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
		}
	}

	// Execute shell based on PTY availability of the peer
	if s.peerInterpreter != nil && s.peerInterpreter.PtyOn {
		return s.executeShellWithPty(sshChan, winChange, envVars)
	}

	return s.executeShellWithoutPty(sshChan, envVars)
}

// executeShellWithPty runs an interactive shell with PTY
func (s *BidirectionalSession) executeShellWithPty(
	channel ssh.Channel,
	winChange <-chan []byte,
	envVars []string,
) error {
	// Get the local execution parameters
	shell := "/bin/bash"
	if s.localInterpreter != nil && s.localInterpreter.Shell != "" {
		shell = s.localInterpreter.Shell
	}

	s.logger.DebugWith("Running SHELL on PTY",
		slog.F("session_id", s.sessionID),
		slog.F("shell", shell))

	cmd := exec.Command(shell)
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
		return fmt.Errorf("start pty: %w", err)
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
	wg.Add(2)

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

	// Copy from SSH channel to PTY
	go func() {
		defer wg.Done()
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

	return nil
}

// executeShellWithoutPty runs a non-interactive shell
func (s *BidirectionalSession) executeShellWithoutPty(
	channel ssh.Channel,
	envVars []string,
) error {
	// Get the local execution parameters
	shell := "/bin/sh"
	system := "linux"
	if s.localInterpreter != nil {
		shell = s.localInterpreter.Shell
		system = s.localInterpreter.System
	}

	s.logger.DebugWith("Running SHELL on NON PTY",
		slog.F("session_id", s.sessionID),
		slog.F("shell", shell))

	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), envVars...)

	// Windows non-PTY shell requires /qa flag
	if system == "windows" {
		cmd.Args = append(cmd.Args, "/qa")
	}

	outRC, oErr := cmd.StdoutPipe()
	if oErr != nil {
		s.logger.ErrorWith("Failed to get stdout pipe",
			slog.F("session_id", s.sessionID),
			slog.F("err", oErr))
		return oErr
	}
	errRC, eErr := cmd.StderrPipe()
	if eErr != nil {
		s.logger.ErrorWith("Failed to get stderr pipe",
			slog.F("session_id", s.sessionID),
			slog.F("err", eErr))
		return eErr
	}

	cmd.Stdin = channel

	if runErr := cmd.Start(); runErr != nil {
		s.logger.ErrorWith("Failed to execute command",
			slog.F("session_id", s.sessionID),
			slog.F("err", runErr))
		return runErr
	}

	go func() { _, _ = io.Copy(channel, outRC) }()
	go func() { _, _ = io.Copy(channel, errRC) }()

	if wErr := cmd.Wait(); wErr != nil {
		s.logger.ErrorWith("Failed to wait for command",
			slog.F("session_id", s.sessionID),
			slog.F("err", wErr))
		return wErr
	}

	s.logger.DebugWith("Non-PTY shell completed",
		slog.F("session_id", s.sessionID))
	return nil
}

// ========================================
// Exec Handler
// ========================================

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
	defer close(winChange)
	envChange := make(chan []byte, 10)

	// Extract command from ExtraData
	// First 4 elements are 3 null bytes plus the size of the payload
	s.logger.DebugWith("Channel ExtraData",
		slog.F("session_id", s.sessionID),
		slog.F("extra_data", nc.ExtraData()))

	rcvCmd := string(nc.ExtraData()[4:])

	// Handle SSH requests
	go s.handleSSHRequests(requests, winChange, envChange)

	// Collect environment variables
	var envVars []string
	for envBytes := range envChange {
		var kv struct{ Key, Value string }
		_ = ssh.Unmarshal(envBytes, &kv)
		if kv.Key == "SLIDER_ENV" && kv.Value == "true" {
			close(envChange)
		} else {
			envVars = append(envVars, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			s.logger.DebugWith("Adding environment variable",
				slog.F("session_id", s.sessionID),
				slog.F("key", kv.Key),
				slog.F("value", kv.Value))
		}
	}

	// Execute command
	var exitCode int
	if s.peerInterpreter != nil && s.peerInterpreter.PtyOn {
		exitCode, err = s.executeCommandWithPty(rcvCmd, sshChan, winChange, envVars)
	} else {
		exitCode, err = s.executeCommandWithoutPty(rcvCmd, sshChan, envVars)
	}

	// Send exit status (always send, even on error)
	exitPayload := make([]byte, 4)
	exitPayload[0] = byte(exitCode >> 24)
	exitPayload[1] = byte(exitCode >> 16)
	exitPayload[2] = byte(exitCode >> 8)
	exitPayload[3] = byte(exitCode)
	_, _ = sshChan.SendRequest("exit-status", false, exitPayload)

	return err
}

// executeCommandWithPty runs command with PTY
func (s *BidirectionalSession) executeCommandWithPty(
	command string,
	channel ssh.Channel,
	winChange <-chan []byte,
	envVars []string,
) (int, error) {
	// Get the local execution parameters
	shell := "/bin/bash"
	var cmdArgs []string
	if s.localInterpreter != nil && s.localInterpreter.Shell != "" {
		shell = s.localInterpreter.Shell
		cmdArgs = s.localInterpreter.CmdArgs
	}

	s.logger.DebugWith("Running EXEC on PTY",
		slog.F("session_id", s.sessionID),
		slog.F("cmd", command))

	cmd := exec.Command(shell, append(cmdArgs, command)...)
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
	wg.Add(2)

	// Copy from PTY to SSH channel
	go func() {
		defer wg.Done()
		_, copyErr := io.Copy(channel, ptyF)
		if copyErr != nil && copyErr != io.EOF {
			s.logger.DebugWith("Error copying from PTY to SSH",
				slog.F("session_id", s.sessionID),
				slog.F("err", copyErr))
		}
		_ = channel.CloseWrite()
	}()

	// Copy from SSH channel to PTY
	go func() {
		defer wg.Done()
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
) (int, error) {
	// Get the local execution parameters
	shell := "/bin/sh"
	var cmdArgs []string
	system := "linux"
	if s.localInterpreter != nil {
		shell = s.localInterpreter.Shell
		cmdArgs = s.localInterpreter.CmdArgs
		system = s.localInterpreter.System
	}

	s.logger.DebugWith("Running EXEC on NON PTY",
		slog.F("session_id", s.sessionID),
		slog.F("cmd", command))

	cmd := exec.Command(shell, append(cmdArgs, command)...)
	cmd.Env = append(os.Environ(), envVars...)

	// Windows non-PTY shell requires /qa flag
	if system == "windows" {
		cmd.Args = append(cmd.Args, "/qa")
	}

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

	go func() { _, _ = io.Copy(channel, outRC) }()
	go func() { _, _ = io.Copy(channel, errRC) }()

	if wErr := cmd.Wait(); wErr != nil {
		s.logger.ErrorWith("Failed to wait for command",
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

// ========================================
// SFTP Handler
// ========================================

// HandleSFTP processes an SFTP channel for ANY role
func (s *BidirectionalSession) HandleSFTP(nc ssh.NewChannel) error {
	s.logger.DebugWith("Handling SFTP channel",
		slog.F("session_id", s.sessionID),
		slog.F("role", s.role.String()))

	sftpChan, requests, err := nc.Accept()
	if err != nil {
		s.logger.ErrorWith("Failed to accept SFTP channel",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}
	defer func() {
		s.logger.DebugWith("Closing SFTP channel",
			slog.F("session_id", s.sessionID))
		_ = sftpChan.Close()
	}()

	s.AddChannel(sftpChan)

	// Handle channel requests in the background
	go ssh.DiscardRequests(requests)

	// Create SFTP server options
	var serverOptions []sftp.ServerOption
	if s.logger.IsDebug() {
		serverOptions = append(serverOptions, sftp.WithDebug(os.Stderr))
	}

	// Determine working directory
	if s.sftpWorkingDir != "" {
		serverOptions = append(serverOptions,
			sftp.WithServerWorkingDirectory(s.sftpWorkingDir))
	}

	// Create the SFTP server
	s.logger.DebugWith("Initializing SFTP server",
		slog.F("session_id", s.sessionID))

	server, err := sftp.NewServer(sftpChan, serverOptions...)
	if err != nil {
		s.logger.ErrorWith("Failed to create SFTP server",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}
	defer server.Close()

	// Serve SFTP requests
	if err := server.Serve(); err != nil && err != io.EOF {
		s.logger.ErrorWith("SFTP server error",
			slog.F("session_id", s.sessionID),
			slog.F("err", err))
		return err
	}

	s.logger.DebugWith("SFTP session completed",
		slog.F("session_id", s.sessionID))
	return nil
}
