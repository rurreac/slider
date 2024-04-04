//go:build windows

package interpreter

import (
	"fmt"
	"github.com/UserExistsError/conpty"
	"golang.org/x/sys/windows"
	"os"
	"os/user"
	"runtime"
	"strings"
	"syscall"
)

type Interpreter struct {
	Arch              string   `json:"Arch"`
	System            string   `json:"System"`
	User              string   `json:"User"`
	Hostname          string   `json:"Hostname"`
	Shell             string   `json:"Shell"`
	ShellArgs         []string `json:"ShellArgs"`
	CmdArgs           []string `json:"CmdArgs"`
	PtyOn             bool     `json:"PtyOn"`
	WinChangeCall     syscall.Signal
	Pty               *conpty.ConPty
	PathSeparator     string
	PathListSeparator string
}

type TermSize struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
}

func IsPtyOn() bool {
	available := conpty.IsConPtyAvailable()
	if available {
		// Even when ConPTY is available, if Slider is not running on a Windows Terminal, control
		// character sequences are not available until an OS command is invoked within Slider.
		// This is somehow normal Windows behavior, but breaks the character output until it happens.
		// The reason is cause ENABLE_VIRTUAL_TERMINAL_PROCESSING and ENABLE_PROCESSED_OUTPUT are not
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

func NewInterpreter() (*Interpreter, error) {
	// TODO: Logic to decide running "cmd" or "powershell" (default to "cmd")
	i := &Interpreter{}

	i.Arch = runtime.GOARCH
	i.System = runtime.GOOS
	var hErr error
	i.Hostname, hErr = os.Hostname()
	if hErr != nil {
		i.Hostname = "--"
	}
	i.User = "--"
	if u, uErr := user.Current(); uErr == nil {
		i.User = u.Username
		fUserName := strings.Split(u.Username, string(os.PathSeparator))
		// If the username does not identify a Domain User
		// remove the hostname part from the username
		if fUserName[0] == i.Hostname {
			i.User = fUserName[1]
		}
	}

	if conpty.IsConPtyAvailable() {
		i.PtyOn = true
	}

	var winCmd = "Windows\\system32\\cmd.exe"
	systemDrive := os.Getenv("SYSTEMDRIVE")
	if systemDrive == "" {
		// Try default if not automatically detected
		systemDrive = "C:"
	}
	i.Shell = fmt.Sprintf("%s\\%s", systemDrive, winCmd)
	i.CmdArgs = []string{"/c"}

	return i, nil
}
