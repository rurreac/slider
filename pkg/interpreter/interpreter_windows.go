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

	"golang.org/x/sys/windows"
)

const (
	cmdPrompt = "Windows\\system32\\cmd.exe"
	pShell    = "Windows\\System32\\WindowsPowershell\\v1.0\\powershell.exe"
)

type Interpreter struct {
	Arch        string   `json:"Arch"`
	System      string   `json:"System"`
	User        string   `json:"User"`
	HomeDir     string   `json:"HomeDir"`
	Hostname    string   `json:"Hostname"`
	Shell       string   `json:"Shell"`
	AltShell    string   `json:"AltShell"`
	ShellArgs   []string `json:"ShellArgs"`
	CmdArgs     []string `json:"CmdArgs"`
	PtyOn       bool     `json:"PtyOn"`
	Pty         Pty
	inputModes  uint32
	outputModes uint32
}

type winPty struct {
	con *conpty.ConPty
}

func (p *winPty) Read(b []byte) (n int, err error)  { return p.con.Read(b) }
func (p *winPty) Write(b []byte) (n int, err error) { return p.con.Write(b) }
func (p *winPty) Close() error                      { return p.con.Close() }
func (p *winPty) Resize(cols, rows uint32) error {
	return p.con.Resize(int(cols), int(rows))
}

func (p *winPty) Wait() error {
	_, err := p.con.Wait(context.Background())
	return err
}

func StartPty(cmd *exec.Cmd, cols, rows uint32) (Pty, error) {
	// Build the command line for Windows.
	// On Windows, conpty.Start (CreateProcess) expects a single command line string.
	// cmd.String() correctly joins and quotes the arguments since Go 1.17.
	commandLine := cmd.String()

	c, err := conpty.Start(commandLine, conpty.ConPtyDimensions(int(cols), int(rows)), conpty.ConPtyEnv(cmd.Env))
	if err != nil {
		return nil, err
	}
	return &winPty{con: c}, nil
}

func IsPtyOn() bool {
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
	i.HomeDir = "C:\\"
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

	i.PtyOn = conpty.IsConPtyAvailable()

	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		// Try default if not automatically detected
		systemDrive = "C:"
	}
	// We default to always using Command Prompt as it is safer when launching from Term, and
	// also some security controls do not apply to it
	i.Shell = fmt.Sprintf("%s\\%s", systemDrive, cmdPrompt)
	i.AltShell = fmt.Sprintf("%s\\%s", systemDrive, pShell)
	i.ShellArgs = []string{}
	i.CmdArgs = []string{"/c"}

	return i, nil
}
