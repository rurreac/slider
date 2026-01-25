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

const (
	shellSeparator = ";"
)

type Interpreter struct {
	BaseInfo
	Shell             string   `json:"Shell"`
	ShellSeparator    string   `json:"ShellSeparator"`
	ShellArgs         []string `json:"ShellArgs"`
	ShellExecArgs     []string `json:"ShellExecArgs"`
	AltShell          string   `json:"AltShell"`
	AltShellSeparator string   `json:"AltShellSeparator"`
	AltShellArgs      []string `json:"AltShellArgs"`
	AltShellExecArgs  []string `json:"AltShellExecArgs"`
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
		"/bin/fish",
	}
	cmdArgs = []string{"-c"}
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

func isPtyOn() bool {
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

	i.PtyOn = isPtyOn()
	i.ColorOn = isColorOn()

	// ZSH on non-PTY breaks I/O assignment; use safe shell to avoid stdin issues
	i.Shell = os.Getenv("SHELL")
	if (i.Shell == "" || strings.Contains(i.Shell, "zsh")) && !i.PtyOn {
		i.Shell = findSafeShell()
	} else if i.Shell == "" && i.PtyOn {
		i.Shell = findNixShell()
	}
	i.ShellSeparator = shellSeparator
	i.ShellArgs = []string{"-i"}
	i.ShellExecArgs = cmdArgs

	i.AltShell = findSafeShell()
	i.AltShellSeparator = shellSeparator
	i.AltShellArgs = []string{}
	i.AltShellExecArgs = cmdArgs

	if i.Shell == "" {
		return nil, fmt.Errorf("can not find a suitable shell on system %s", i.System)
	}

	if i.Shell == "" {
		return nil, fmt.Errorf("can not find a suitable shell on system %s", i.System)
	}

	// Capture binary path
	if exe, err := os.Executable(); err == nil {
		i.SliderDir = exe
	}

	// Capture initial working directory
	var err error
	i.LaunchDir, err = os.Getwd()
	if err != nil {
		i.LaunchDir = i.HomeDir
	}

	return i, nil
}

// isColorOn checks if colors are enabled on the system by checking known environment variables
func isColorOn() bool {
	// System requests not to enable colors (by convention: https://no-color.org/)
	if os.Getenv("NO_COLOR") != "" {
		return false
	}

	// Terminal supports colors
	if strings.Contains(os.Getenv("TERM"), "colors") {
		return true
	}

	// A color range is supported
	colorTerm := os.Getenv("COLORTERM")
	if strings.Contains(colorTerm, "truecolor") || strings.Contains(colorTerm, "24bit") {
		return true
	}

	// System enables colors (macOS/BSD)
	cliColor := os.Getenv("CLICOLOR")
	cliColorForce := os.Getenv("CLICOLOR_FORCE")
	if cliColor == "1" || cliColorForce == "1" {
		return true
	}

	return false
}
