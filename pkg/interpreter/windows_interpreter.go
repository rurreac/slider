//go:build windows

package interpreter

import (
	"fmt"
	"github.com/UserExistsError/conpty"
	"os"
	"os/user"
	"runtime"
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

func NewInterpreter() (*Interpreter, error) {
	// TODO: Logic to decide running "cmd" or "powershell" (default to "cmd")
	i := &Interpreter{}

	i.Arch = runtime.GOARCH
	i.System = runtime.GOOS
	i.User = "--"
	if u, uErr := user.Current(); uErr == nil {
		i.User = u.Username
	}
	var hErr error
	i.Hostname, hErr = os.Hostname()
	if hErr != nil {
		i.Hostname = "--"
	}

	// TODO: Default path but might not be this one
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
