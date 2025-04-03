//go:build !windows

package client

import (
	"fmt"
	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
	"io"
	"os/exec"
	"slider/pkg/instance"
	"slider/pkg/sio"
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
	defer func() { _ = sshChan.Close() }()

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
			s.Logger.Debugf("Adding Environment variable: %s=\"%s\"\n", kv.Key, kv.Value)
		}
	}

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
					s.Logger.Debugf("Failed to set window size: %v", sErr)
				}
			}
		}()

		_, _ = sio.PipeWithCancel(ptyF, sshChan)

	} else {
		s.Logger.Debugf("Running SHELL on NON PTY")
		outRC, oErr := cmd.StdoutPipe()
		if oErr != nil {
			s.Logger.Errorf("Failed to get stdout pipe %v", oErr)
			return
		}
		errRC, eErr := cmd.StderrPipe()
		if eErr != nil {
			s.Logger.Errorf("Failed to get stderr pipe %v", eErr)
			return
		}

		if runErr := cmd.Start(); runErr != nil {
			s.Logger.Errorf("Failed to execute command error - %v", runErr)
			return
		}

		// Handle window-change events
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				size := []string{
					fmt.Sprintf("LINES=%d", int(cols)),
					fmt.Sprintf("COLUMNS=%d", int(rows)),
				}
				for _, envVar := range size {
					cmd.Env = append(cmd.Environ(), envVar)
				}
			}
		}()

		go func() { _, _ = io.Copy(sshChan, outRC) }()
		go func() { _, _ = io.Copy(sshChan, errRC) }()

		if wErr := cmd.Wait(); wErr != nil {
			s.Logger.Errorf("Failed to wait for command error - %v", wErr)
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
	defer func() { _ = sshChan.Close() }()

	winChange := make(chan []byte, 10)
	defer close(winChange)

	// This channel will be a blocker and closed by the server request
	envChange := make(chan []byte, 10)

	// First 4 elements of Channel.Extradata() are 3 null bytes plus the size of the payload
	// The rest of the payload is the command to be executed
	s.Logger.Debugf("ExtraData: %v", channel.ExtraData())

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
			s.Logger.Debugf("Adding Environment variable: %s=\"%s\"\n", kv.Key, kv.Value)
		}
	}

	if s.interpreter.PtyOn {
		s.Logger.Debugf("Running EXEC on PTY")
		ptyF, fErr := pty.Start(cmd)
		if fErr != nil {
			s.Logger.Errorf("Failed to start command %v", fErr)
			return
		}
		defer func() { _ = ptyF.Close() }()

		// Handle window changes
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				if sErr := pty.Setsize(ptyF, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)}); sErr != nil {
					s.Logger.Debugf("Failed to set window size: %v", sErr)
				}
			}
		}()

		_, _ = sio.PipeWithCancel(ptyF, sshChan)

	} else {
		s.Logger.Debugf("Running EXEC on NON PTY")
		outRC, oErr := cmd.StdoutPipe()
		if oErr != nil {
			s.Logger.Errorf("Failed to get stdout pipe %v", oErr)
			return
		}
		errRC, eErr := cmd.StderrPipe()
		if eErr != nil {
			s.Logger.Errorf("Failed to get stderr pipe %v", eErr)
			return
		}

		if runErr := cmd.Start(); runErr != nil {
			s.Logger.Errorf("Failed to execute command error - %v", runErr)
			return
		}

		// Handle window-change events
		go func() {
			for sizeBytes := range winChange {
				cols, rows := instance.ParseSizePayload(sizeBytes)
				size := []string{
					fmt.Sprintf("LINES=%d", int(cols)),
					fmt.Sprintf("COLUMNS=%d", int(rows)),
				}
				for _, envVar := range size {
					cmd.Env = append(cmd.Environ(), envVar)
				}
			}
		}()

		go func() { _, _ = io.Copy(sshChan, outRC) }()
		go func() { _, _ = io.Copy(sshChan, errRC) }()

		if wErr := cmd.Wait(); wErr != nil {
			s.Logger.Errorf("Failed to wait for command error - %v", wErr)
		}
	}

}
