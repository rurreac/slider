//go:build windows

package interpreter

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"

	"github.com/rurreac/conpty"
	"golang.org/x/sys/windows"
)

const (
	cmdPrompt          = "Windows\\system32\\cmd.exe"
	cmdPromptSeparator = "&"
	pShell             = "Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe"
	pShellSeparator    = ";"
)

var (
	cmdPromptArgs     = []string{"/qa"}
	cmdPromptExecArgs = []string{"/qa", "/c"}
	pShellArgs        = []string{}
	pShellExecArgs    = []string{"-Command"}
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
	inputModes        uint32
	outputModes       uint32
}

type winPty struct {
	con *conpty.LocalConPty
}

func (p *winPty) Read(b []byte) (n int, err error)  { return p.con.Read(b) }
func (p *winPty) Write(b []byte) (n int, err error) { return p.con.Write(b) }
func (p *winPty) Close() error                      { return p.con.Close() }
func (p *winPty) Resize(cols, rows uint32) error    { return p.con.Resize(int(cols), int(rows)) }
func (p *winPty) Wait() error {
	_, err := p.con.Wait(context.Background())
	return err
}

// StartPty creates a new PTY.
func StartPty(cmd *exec.Cmd, cols, rows uint32) (Pty, error) {
	commandLine := cmd.String()

	// Enable cursor inheritance and raw console mode
	options := []conpty.ConPtyOption{
		conpty.WithInheritCursor(true),
	}
	c, err := conpty.StartConPty(commandLine, int(cols), int(rows), cmd.Env, options...)
	if err != nil {
		return nil, err
	}

	return &winPty{con: c}, nil
}

func isPtyOn() bool {
	available := conpty.IsConPtyAvailable()
	if available {
		outHandle := windows.Handle(os.Stdout.Fd())
		var mode uint32
		if err := windows.GetConsoleMode(outHandle, &mode); err == nil {
			_ = windows.SetConsoleMode(outHandle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT)
		}
		errHandle := windows.Handle(os.Stderr.Fd())
		if err := windows.GetConsoleMode(errHandle, &mode); err == nil {
			_ = windows.SetConsoleMode(errHandle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT)
		}
	}
	return available
}

func (i *Interpreter) EnableProcessedInputOutput() error {
	// Best effort, set ENABLE_PROCESSED_INPUT always to properly handle input in a raw terminal
	// even in old Windows versions
	inHandle := windows.Handle(os.Stdin.Fd())
	var inMode uint32
	if err := windows.GetConsoleMode(inHandle, &inMode); err != nil {
		return err
	}
	i.inputModes = inMode
	// Enable virtual terminal input processing for backspace handling
	newInMode := inMode | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	if err := windows.SetConsoleMode(inHandle, newInMode); err != nil {
		// Non-fatal, older windows might not support VT Input
	}

	outHandle := windows.Handle(os.Stdout.Fd())
	var outMode uint32
	if err := windows.GetConsoleMode(outHandle, &outMode); err == nil {
		i.outputModes = outMode
		newOutMode := outMode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.ENABLE_PROCESSED_OUTPUT
		_ = windows.SetConsoleMode(outHandle, newOutMode)
	}

	errHandle := windows.Handle(os.Stderr.Fd())
	var errMode uint32
	if err := windows.GetConsoleMode(errHandle, &errMode); err == nil {
		newErrMode := errMode | windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING | windows.ENABLE_PROCESSED_OUTPUT
		_ = windows.SetConsoleMode(errHandle, newErrMode)
	}

	return nil
}

func (i *Interpreter) ResetInputOutputModes() error {
	inHandle := windows.Handle(os.Stdin.Fd())
	if err := windows.SetConsoleMode(inHandle, i.inputModes); err != nil {
		return err
	}

	outHandle := windows.Handle(os.Stdout.Fd())
	if err := windows.SetConsoleMode(outHandle, i.outputModes); err != nil {
		return err
	}

	errHandle := windows.Handle(os.Stderr.Fd())
	return windows.SetConsoleMode(errHandle, i.outputModes)
}

func NewInterpreter() (*Interpreter, error) {
	i := &Interpreter{}

	i.Arch = runtime.GOARCH
	i.System = runtime.GOOS
	var hErr error
	i.Hostname, hErr = os.Hostname()
	if hErr != nil {
		i.Hostname = "--"
	}
	i.User = "--"
	i.HomeDir = os.Getenv("USERPROFILE")
	if u, uErr := user.Current(); uErr == nil {
		i.User = u.Username
		i.HomeDir = u.HomeDir
		fUserName := strings.Split(u.Username, string(os.PathSeparator))
		// If the username does not identify a Domain User,
		// remove the hostname part from the username
		if fUserName[0] == i.Hostname {
			i.User = fUserName[1]
		}
	}

	i.PtyOn = isPtyOn()
	// It is safe to assume that if PTY is On then colors are supported.
	// We are mainly filtering old Windows versions.
	i.ColorOn = i.PtyOn

	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		// Try default if not automatically detected
		systemDrive = "C:"
	}
	i.Shell = fmt.Sprintf("%s\\%s", systemDrive, cmdPrompt)
	i.ShellSeparator = cmdPromptSeparator
	i.ShellArgs = cmdPromptArgs
	i.ShellExecArgs = cmdPromptExecArgs

	i.AltShell = fmt.Sprintf("%s\\%s", systemDrive, pShell)
	i.AltShellSeparator = pShellSeparator
	i.AltShellArgs = pShellArgs
	i.AltShellExecArgs = pShellExecArgs

	// Capture binary path
	if exe, err := os.Executable(); err == nil {
		i.SliderDir = exe
	}
	// Capture initial working directory
	if wd, err := os.Getwd(); err == nil {
		i.LaunchDir = wd
	}
	return i, nil
}
