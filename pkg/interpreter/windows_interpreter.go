//go:build windows

package interpreter

import (
	"fmt"
	"os"
	"syscall"
)

type Interpreter struct {
	Shell         string
	ShellArgs     []string
	CmdArgs       []string
	PtyOn         bool
	WinChangeCall syscall.Signal
	Pty           *conpty.ConPty
}

type TermSize struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
}

func NewInterpreter() (*Interpreter, error) {
	// TODO: Logic to decide running "cmd" or "powershell" (default to "cmd")
	i := &Interpreter{}

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
