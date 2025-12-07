//go:build windows

package interpreter

import (
	"fmt"
	"os"
	"os/user"
	"runtime"
	"strings"

	"github.com/UserExistsError/conpty"
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
	Pty         *conpty.ConPty
	inputModes  uint32
	outputModes uint32
}

func IsPtyOn() bool {
	available := conpty.IsConPtyAvailable()
	// We do this now so we can have logs with colors, and this is needed even before having an interpreter
	if available {
		// Even when ConPTY is available, if Slider is not running on a Windows Terminal, control
		// character sequences are not available until an OS command is invoked within Slider.
		// This is somehow normal Windows behavior but breaks the character output until it happens.
		// The reason is that ENABLE_VIRTUAL_TERMINAL_PROCESSING and ENABLE_PROCESSED_OUTPUT are not
		// enabled by default.
		// The following will enable those values if they are not, regardless of the terminal, or return false
		outHandle := windows.Handle(os.Stdout.Fd())
		var lpMode uint32
		// https://learn.microsoft.com/en-us/windows/console/getconsolemode
		if err := windows.GetConsoleMode(outHandle, &lpMode); err != nil {
			return false
		}
		// https://learn.microsoft.com/en-us/windows/console/setconsolemode
		if lpMode != windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT {
			if err := windows.SetConsoleMode(outHandle, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT); err != nil {
				return false
			}
			errHandle := windows.Handle(os.Stderr.Fd())
			if err := windows.SetConsoleMode(errHandle, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT); err != nil {
				return false
			}
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
	if inMode != windows.ENABLE_PROCESSED_INPUT|windows.ENABLE_VIRTUAL_TERMINAL_INPUT {
		if err := windows.SetConsoleMode(inHandle, windows.ENABLE_PROCESSED_INPUT|windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err != nil {
			return err
		}
	}
	// Even when ConPTY is available, if Slider is not running on a Windows Terminal, control
	// character sequences are not available until an OS command is invoked within Slider.
	// This is somehow normal Windows behavior but breaks the character output until it happens.
	// The reason is that ENABLE_VIRTUAL_TERMINAL_PROCESSING and ENABLE_PROCESSED_OUTPUT are not
	// enabled by default.
	outHandle := windows.Handle(os.Stdout.Fd())
	var lpMode uint32
	// https://learn.microsoft.com/en-us/windows/console/getconsolemode
	if err := windows.GetConsoleMode(outHandle, &lpMode); err != nil {
		return err
	}
	i.outputModes = lpMode
	// https://learn.microsoft.com/en-us/windows/console/setconsolemode
	if lpMode != windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT {
		if err := windows.SetConsoleMode(outHandle, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT); err != nil {
			return err
		}
		errHandle := windows.Handle(os.Stderr.Fd())
		if err := windows.SetConsoleMode(errHandle, windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.ENABLE_PROCESSED_OUTPUT); err != nil {
			return err
		}
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
	i.AltShell = fmt.Sprintf("%s\\%s", systemDrive, cmdPrompt)
	i.CmdArgs = []string{"/c"}

	return i, nil
}
