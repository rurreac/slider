package server

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slider/pkg/conf"
	"slider/pkg/types"
	"strconv"
	"strings"

	"golang.org/x/term"
)

type Console struct {
	Term      *term.Terminal
	InitState *term.State
	FirstRun  bool
	History   *CustomHistory
}

type screenIO struct {
	io.Reader
	io.Writer
}

func (s *server) consoleBanner() {
	s.console.clearScreen()
	s.console.Printf("%s%s%s\n\n", greyBold, conf.Banner, resetColor)
	s.console.PrintInfo("Type \"bg\" to return to logging.")
	s.console.PrintInfo("Type \"help\" to see available commands.")
	s.console.PrintInfo("Type \"exit\" to exit the console.\n")
}

func (s *server) newTerminal(screen screenIO, registry *CommandRegistry) error {
	var rErr error

	// Not Initializing with os.Stdin will fail on Windows
	_, rErr = term.MakeRaw(int(os.Stdin.Fd()))
	if rErr != nil {
		return rErr
	}

	// Set Console
	s.console.Term = term.NewTerminal(screen, getPrompt())
	s.console.setConsoleAutoComplete(registry)
	s.console.Term.History = s.console.History

	width, height, tErr := term.GetSize(int(os.Stdout.Fd()))
	if tErr != nil {
		return tErr
	}
	if sErr := s.console.Term.SetSize(width, height); sErr != nil {
		return sErr
	}

	if s.console.FirstRun {
		s.consoleBanner()
		s.console.FirstRun = false
	}

	return nil
}

func (s *server) NewConsole() string {
	var out string

	// Only applies to Windows - Best effort to have a successful raw terminal regardless
	// of the Windows version
	if piErr := s.serverInterpreter.EnableProcessedInputOutput(); piErr != nil {
		s.Errorf("Failed to enable Processed Input/Output")
		// Sets Console Colors based on if PTY is enabled on the server.
		// If it's not on PTY and fails to set Processed IO, disables colors
		setConsoleColors()
	}
	defer func() {
		if ioErr := s.serverInterpreter.ResetInputOutputModes(); ioErr != nil {
			s.Errorf("Failed to reset Input/Output modes: %s", ioErr)
		}
	}()

	// Initialize Registry
	s.initRegistry()

	// Set Console
	var sErr error
	s.console.InitState, sErr = term.GetState(int(os.Stdin.Fd()))
	if sErr != nil {
		s.Fatalf("Failed to read terminal size: %v", sErr)
	}
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.console.InitState)
	}()
	screen := screenIO{os.Stdin, os.Stdout}
	if ntErr := s.newTerminal(screen, s.commandRegistry); ntErr != nil {
		s.Fatalf("Failed to initialize terminal: %s", ntErr)
	}

	for consoleInput := true; consoleInput; {
		var fCmd string
		input, err := s.console.Term.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.console.TermPrintf("\rFailed to read input: %s\r\n", err)
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF and kills the terminal.
			// To avoid an unexpected behavior, we will silently create a new terminal
			// and continue
			if ntErr := s.newTerminal(screen, s.commandRegistry); ntErr != nil {
				s.Fatalf("Failed to recover terminal: %s", ntErr)
			}
			_, _ = s.console.Term.Write([]byte{'\n'})
			continue
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)

		if len(args) > 0 {
			fCmd = args[0]
		}

		if fCmd == "" {
			continue
		}

		// This is meant to be a command to execute locally
		if strings.HasPrefix(fCmd, "!") {
			if len(fCmd) > 1 {
				fullCommand := []string{strings.TrimPrefix(fCmd, "!")}
				fullCommand = append(fullCommand, args[1:]...)
				s.notConsoleCommand(fullCommand)
				continue
			}
		}

		cmdParts := args
		command := strings.ToLower(cmdParts[0])
		cmdArgs := cmdParts[1:]

		// Create execution context for regular console (no session)
		ctx := &ExecutionContext{
			server:  s,
			session: nil,
			ui:      &s.console,
		}

		// Try to execute command from registry
		err = s.commandRegistry.Execute(ctx, command, cmdArgs)
		if err != nil {
			if errors.Is(err, ErrExitConsole) {
				out = exitCmd
				consoleInput = false
			} else if errors.Is(err, ErrBackgroundConsole) {
				out = bgCmd
				consoleInput = false
			} else {
				s.console.PrintError("%v", err)
			}
		} else {
			s.console.Term.SetPrompt(getPrompt())
		}
	}

	return out
}

func (c *Console) setConsoleAutoComplete(registry *CommandRegistry) {
	// Simple autocompletion
	c.Term.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		line = strings.TrimSpace(line)
		// If TAB key is pressed and text was written
		if key == 9 && len(line) > 0 {
			newLine, newPos := registry.Autocomplete(line)
			return newLine, newPos, true
		}
		return line, pos, false
	}
}

func autocompleteCommand(input string, cmdList []string) (string, int) {
	// Check if the input matches any command in the list
	var matches []string
	for _, cmd := range cmdList {
		if strings.HasPrefix(cmd, input) {
			matches = append(matches, cmd)
		}
	}

	// If there is only one match, return it
	if len(matches) == 1 {
		return matches[0], len(matches[0])
	}

	// If there are multiple matches, find the common prefix
	if len(matches) > 1 {
		commonPrefix := matches[0]
		for _, match := range matches[1:] {
			for !strings.HasPrefix(match, commonPrefix) {
				commonPrefix = commonPrefix[:len(commonPrefix)-1]
			}
		}
		return commonPrefix, len(commonPrefix)
	}

	return input, len(input)
}

func (s *server) notConsoleCommand(fCmd []string) {
	// If a Shell was not set, just return
	if s.serverInterpreter.Shell == "" {
		s.console.PrintError("No Shell set")
		return
	}

	// Else, we'll try to execute the command locally
	s.console.PrintWarn("Executing local Command: %s", fCmd)
	fCmd = append(s.serverInterpreter.CmdArgs, strings.Join(fCmd, " "))

	cmd := exec.Command(s.serverInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Stdout = s.console.Term
	cmd.Stderr = s.console.Term
	if err := cmd.Run(); err != nil {
		s.console.PrintError("%v", err)
	}
	s.console.Println("")

}

func parsePort(input string) (int, error) {
	remotePort, iErr := strconv.Atoi(input)
	if iErr != nil || remotePort < 1 || remotePort > 65535 {
		return 0, fmt.Errorf("invalid port: %s", input)
	}
	return remotePort, nil
}

func parseForwarding(input string) (*types.CustomTcpIpChannelMsg, error) {
	var remoteAddr, localAddr string
	var remotePort, localPort int
	msg := &types.CustomTcpIpChannelMsg{}

	portFwd := strings.Split(input, ":")

	var iErr error
	switch len(portFwd) {
	case 1:
		localAddr = "localhost"
		remoteAddr = "localhost"
		localPort, iErr = parsePort(portFwd[0])
		if iErr != nil {
			return msg, iErr
		}
		remotePort = localPort
	case 3:
		remoteAddr = "0.0.0.0"
		remotePort, iErr = parsePort(portFwd[0])
		if iErr != nil {
			return msg, iErr
		}
		localAddr = portFwd[1]
		if localAddr == "" {
			localAddr = "localhost"
		}
		localPort, iErr = parsePort(portFwd[2])
		if iErr != nil {
			return msg, iErr
		}
	case 4:
		remoteAddr = portFwd[0]
		remotePort, iErr = parsePort(portFwd[1])
		if iErr != nil {
			return msg, iErr
		}
		localAddr = portFwd[2]
		if localAddr == "" {
			localAddr = "localhost"
		}
		localPort, iErr = parsePort(portFwd[3])
		if iErr != nil {
			return msg, iErr
		}

	default:
		return msg, fmt.Errorf("invalid Port Forwarding format: %s", input)
	}

	msg.IsSshConn = false
	msg.TcpIpChannelMsg = &types.TcpIpChannelMsg{
		DstHost: localAddr,
		DstPort: uint32(localPort),
		SrcHost: remoteAddr,
		SrcPort: uint32(remotePort),
	}

	return msg, nil
}
