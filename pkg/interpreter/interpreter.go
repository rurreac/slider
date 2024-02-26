//go:build !windows

package interpreter

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"
)

type Interpreter struct {
	Shell         string
	ShellArgs     []string
	CmdArgs       []string
	PtyOn         bool
	WinChangeCall syscall.Signal
	Pty           *os.File
}

type TermSize struct {
	Rows int `json:"rows"`
	Cols int `json:"cols"`
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
		"/bin/bash",
		"/bin/sh",
	}
	extShells = []string{
		"/bin/zsh",
		"/bin/csh",
		"/bin/ksh",
		"/bin/tsh",
	}
)

func findNixShell() string {
	// TODO: May want to check if the user has execution rights
	for _, sh := range slices.Concat(safeShells, extShells) {
		if _, err := os.Stat(sh); !os.IsNotExist(err) {
			return sh
		}
	}
	return ""
}

func findSafeShell() string {
	// TODO: May want to check if the user has execution rights
	for _, sh := range safeShells {
		if _, err := os.Stat(sh); !os.IsNotExist(err) {
			return sh
		}
	}
	return ""
}

func NewInterpreter() (*Interpreter, error) {
	// TODO: We may want to let the user choose what shell to run?
	i := &Interpreter{
		WinChangeCall: syscall.SIGWINCH,
	}

	system := runtime.GOOS

	if slices.Contains(nixPty, system) {
		i.PtyOn = true
	}

	// For some reason a combination of non a PTY terminal and a ZSH shell breaks the i/o assignment
	// while sending a reverse shell and the command stdin defaults to io.Stdin.
	// When this happens the Client opens a zsh shell locally and the results of the commands input in
	// this shell are shown on the Slider Server.
	// In order to avoid this issue we will override the Shell for a known working one or nothing
	i.Shell = os.Getenv("SHELL")
	if (i.Shell == "" || strings.Contains(i.Shell, "zsh")) && !i.PtyOn {
		i.Shell = findSafeShell()
	} else if i.Shell == "" && i.PtyOn {
		i.Shell = findNixShell()
	}

	i.ShellArgs = []string{"-i"}
	i.CmdArgs = []string{"-c"}

	if i.Shell == "" {
		return nil, fmt.Errorf("can not find a suitable shell on system %s", system)
	}

	return i, nil
}
