//go:build !windows

package interpreter

import (
	"fmt"
	"os"
	"runtime"
	"slices"
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
	nixShells = []string{
		"/bin/bash",
		"/bin/sh",
		"/bin/zsh",
		"/bin/csh",
		"/bin/ksh",
		"/bin/tsh",
	}
)

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
	// TODO: We may want to let the user choose what shell to run?
	i := &Interpreter{
		WinChangeCall: syscall.SIGWINCH,
	}

	system := runtime.GOOS

	if slices.Contains(nixPty, system) {
		i.PtyOn = true
	}

	// Handle any *Nix like OS
	if shellEnv := os.Getenv("SHELL"); shellEnv != "" {
		i.Shell = shellEnv
	} else {
		i.Shell = findNixShell()
	}
	i.ShellArgs = []string{"-i"}
	i.CmdArgs = []string{"-c"}

	if i.Shell == "" {
		return nil, fmt.Errorf("can not find a suitable shell on system %s", system)
	}

	return i, nil
}
