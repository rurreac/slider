//go:build !windows

package interpreter

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"slices"
	"strings"

	"github.com/creack/pty"
)

type Interpreter struct {
	Arch      string   `json:"Arch"`
	System    string   `json:"System"`
	User      string   `json:"User"`
	HomeDir   string   `json:"HomeDir"`
	Hostname  string   `json:"Hostname"`
	Shell     string   `json:"Shell"`
	AltShell  string   `json:"AltShell"`
	ShellArgs []string `json:"ShellArgs"`
	CmdArgs   []string `json:"CmdArgs"`
	PtyOn     bool     `json:"PtyOn"`
	Pty       Pty
}

type unixPty struct {
	file *os.File
	cmd  *exec.Cmd
}

func (p *unixPty) Read(b []byte) (n int, err error)  { return p.file.Read(b) }
func (p *unixPty) Write(b []byte) (n int, err error) { return p.file.Write(b) }
func (p *unixPty) Close() error                      { return p.file.Close() }
func (p *unixPty) Resize(cols, rows uint32) error {
	return pty.Setsize(p.file, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}
func (p *unixPty) Wait() error {
	return p.cmd.Wait()
}

func StartPty(cmd *exec.Cmd, cols, rows uint32) (Pty, error) {
	f, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
	if err != nil {
		return nil, err
	}
	return &unixPty{file: f, cmd: cmd}, nil
}

var (
	// *nix systems that supports pty
	nixPty = []string{
		"linux",
		"darwin",
		"dragonfly",
		"freebsd",
		"illumos",
		"netbsd",
		"openbsd",
		"solaris",
	}
	// common *nix shells
	safeShells = []string{
		"/bin/sh",
	}
	extShells = []string{
		"/bin/zsh",
		"/bin/bash",
		"/bin/csh",
		"/bin/ksh",
		"/bin/tsh",
	}
)

func findNixShell() string {
	for _, sh := range slices.Concat(safeShells, extShells) {
		if _, err := os.Stat(sh); !os.IsNotExist(err) {
			return sh
		}
	}
	return ""
}

func findSafeShell() string {
	for _, sh := range safeShells {
		if _, err := os.Stat(sh); !os.IsNotExist(err) {
			return sh
		}
	}
	return ""
}

func IsPtyOn() bool {
	return slices.Contains(nixPty, runtime.GOOS)
}

func (i *Interpreter) EnableProcessedInputOutput() error {
	return nil
}

func (i *Interpreter) ResetInputOutputModes() error {
	return nil
}

func NewInterpreter() (*Interpreter, error) {
	i := &Interpreter{}

	i.Arch = runtime.GOARCH
	i.System = runtime.GOOS
	i.User = "--"
	i.HomeDir = "/"
	if u, uErr := user.Current(); uErr == nil {
		i.User = u.Username
		i.HomeDir = u.HomeDir
	}
	var hErr error
	i.Hostname, hErr = os.Hostname()
	if hErr != nil {
		i.Hostname = "--"
	}

	i.PtyOn = IsPtyOn()

	// ZSH on non-PTY breaks I/O assignment; use safe shell to avoid stdin issues
	i.Shell = os.Getenv("SHELL")
	if (i.Shell == "" || strings.Contains(i.Shell, "zsh")) && !i.PtyOn {
		i.Shell = findSafeShell()
	} else if i.Shell == "" && i.PtyOn {
		i.Shell = findNixShell()
	}
	i.AltShell = findSafeShell()
	i.ShellArgs = []string{"-i"}
	i.CmdArgs = []string{"-c"}

	if i.Shell == "" {
		return nil, fmt.Errorf("can not find a suitable shell on system %s", i.System)
	}

	return i, nil
}
