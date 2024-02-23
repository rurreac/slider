package interpreter

import (
	"fmt"
	"os"
	"runtime"
)

type TermSize struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
}

type Interpreter struct {
	Shell     string
	ShellArgs []string
	CmdArgs   []string
	Pty       string
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

func NewInterpreter() (*Interpreter, error) {
	i := &Interpreter{}

	system := runtime.GOOS

	switch system {
	case "darwin":
		// Use explicitly "bash" cause exists and "zsh" adds an extra "\n%" after return
		i.Shell = "/bin/bash"
		i.Pty = "pty"
		// Make it interactive. Among other things will show prompt
		i.ShellArgs = []string{"-i"}
		i.CmdArgs = []string{"-c"}

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
		i.Shell = fmt.Sprintf("%s\\%s", systemDrive, winCmd)
		i.CmdArgs = []string{"/c"}
	case "linux":
		i.Pty = "pty"
		fallthrough
	default:
		// Handle any *Nix like OS
		if shellEnv := os.Getenv("SHELL"); shellEnv != "" {
			i.Shell = shellEnv
		} else {
			i.Shell = findNixShell()
		}
		i.ShellArgs = []string{"-i"}
		i.CmdArgs = []string{"-c"}
	}

	if i.Shell == "" {
		return nil, fmt.Errorf("can not find a suitable shell on system %s", system)
	}

	return i, nil
}
