package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/pkg/sftp"
)

// newSftpConsole provides an interactive SFTP session
func (s *server) newSftpConsole(session *Session, sftpClient *sftp.Client) {
	// Get current directory
	localCwd, clErr := os.Getwd()
	if clErr != nil {
		localCwd = ""
		s.console.PrintError("Unable to determine local directory: %v", clErr)
	}
	// Get current remote directory for prompt
	remoteCwd, crErr := sftpClient.Getwd()
	if crErr != nil {
		remoteCwd = ""
		s.console.PrintError("Unable to determine remote directory: %v", crErr)
	}

	// Set client and server info
	cliHomeDir := session.clientInterpreter.HomeDir
	cliSystem := strings.ToLower(session.clientInterpreter.System)
	svrSystem := strings.ToLower(s.serverInterpreter.System)

	// Fixing some path inconsistencies between SFTP client and server
	if cliSystem == "windows" && svrSystem != "windows" /*&& !session.clientInterpreter.PtyOn*/ {
		cliHomeDir = strings.ReplaceAll(cliHomeDir, "/", "\\")
		remoteCwd = strings.ReplaceAll(strings.TrimPrefix(remoteCwd, "/"), "/", "\\")
	}
	if cliSystem == "windows" && svrSystem == "windows" {
		cliHomeDir = strings.ReplaceAll(cliHomeDir, "\\", "/")
		remoteCwd = strings.TrimPrefix(remoteCwd, "/")
	}
	if cliSystem != "windows" && svrSystem == "windows" {
		remoteCwd = strings.ReplaceAll(remoteCwd, "\\", "/")
	}

	cliUser := strings.ToLower(session.clientInterpreter.User)
	cliHostname := strings.ToLower(session.clientInterpreter.Hostname)

	// Define SFTP prompt
	sftpPrompt := func() string {
		rCwd := remoteCwd
		if strings.HasPrefix(remoteCwd, cliHomeDir) {
			rCwd = strings.Replace(remoteCwd, cliHomeDir, "~", 1)
		}

		return fmt.Sprintf(
			"\r(%s) %s@%s:%s%s ",
			cyanBoldText(fmt.Sprintf("S%d", session.sessionID)),
			cliUser,
			cliHostname,
			rCwd,
			cyanBoldText("$"),
		)

	}

	// Print welcome message and help info
	s.console.PrintInfo("Starting interactive session")
	s.console.PrintInfo("Type \"help\" for available commands")
	s.console.PrintInfo("Type \"exit\" or press \"CTRL^C\" to return to Console")

	// Initialize SFTP command registry
	s.initSftpRegistry(session, sftpClient, &remoteCwd, &localCwd)

	// Set the terminal prompt and autocomplete
	s.console.Term.SetPrompt(sftpPrompt())
	s.console.setSftpConsoleAutoComplete(session.sftpCommandRegistry)

	// Replace Console History with own History for SFTP Session
	s.console.Term.History = session.SftpHistory

	for {
		input, rErr := s.console.Term.ReadLine()
		if rErr != nil {
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF and kills the terminal.
			// When this happens, we will return to the main Console
			return
		}

		cmdParts := fieldsWithQuotes(input)

		if len(cmdParts) < 1 {
			continue
		}

		if cmdParts[0] == "" {
			continue
		}
		command := strings.ToLower(cmdParts[0])
		args := cmdParts[1:]

		// Create execution context for SFTP console (with session)
		ctx := &ExecutionContext{
			server:  s,
			session: session,
			ui:      &s.console,
		}

		// Process commands
		switch command {
		case "shell":
			eArgs := []string{"-s", fmt.Sprintf("%d", session.sessionID), "-i"}
			_ = s.commandRegistry.Execute(ctx, "shell", eArgs)
		case "execute":
			if len(args) < 1 {
				s.console.PrintWarn("Nothing to execute\n")
				continue
			}
			// Prepend cd command to execute from remoteCwd
			commandStr := strings.Join(args, " ")
			commandWithCd := fmt.Sprintf("cd %s && %s", remoteCwd, commandStr)
			eArgs := []string{"-s", fmt.Sprintf("%d", session.sessionID), commandWithCd}
			_ = s.commandRegistry.Execute(ctx, "execute", eArgs)
			continue
		default:
			// This is meant to be a command to execute locally
			if strings.HasPrefix(command, "!") {
				if len(command) > 1 {
					fullCommand := []string{strings.TrimPrefix(command, "!")}
					fullCommand = append(fullCommand, args...)
					s.notConsoleCommandWithDir(fullCommand, localCwd)
					continue
				}
			}

			// Try to execute command from SFTP registry
			err := session.sftpCommandRegistry.Execute(ctx, command, args)
			if err != nil {
				if errors.Is(err, ErrExitConsole) {
					// Set Console History back
					s.console.Term.History = s.console.History
					// Exit SFTP session
					return
				}
				s.console.PrintError("%v", err)
			}
			s.console.Term.SetPrompt(sftpPrompt())
		}
	}
}

// notConsoleCommandWithDir executes a local command from a specified working directory (SFTP-specific)
func (s *server) notConsoleCommandWithDir(fCmd []string, workingDir string) {
	// If a Shell was not set, just return
	if s.serverInterpreter.Shell == "" {
		s.console.PrintError("No Shell set")
		return
	}

	// Else, we'll try to execute the command locally from the specified directory
	s.console.PrintWarn("Executing local Command: %s", fCmd)
	fCmd = append(s.serverInterpreter.CmdArgs, strings.Join(fCmd, " "))

	cmd := exec.Command(s.serverInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Dir = workingDir                                    // Set working directory
	cmd.Stdout = s.console.Term
	cmd.Stderr = s.console.Term
	if err := cmd.Run(); err != nil {
		s.console.PrintError("%v", err)
	}
	s.console.Println("")
}

func fieldsWithQuotes(input string) []string {
	quoted := false
	fields := strings.FieldsFunc(input, func(r rune) bool {
		if r == '"' {
			quoted = true
		}
		return !quoted && r == ' '
	})
	newFields := make([]string, 0)
	for _, item := range fields {
		// Each quoted item must open and close quotes to be considered a field
		nq := strings.Count(item, "\"")
		if nq == 1 {
			newFields = append(newFields, item)
			continue
		}

		if nq%2 == 0 {
			newFields = append(newFields, strings.ReplaceAll(item, "\"", ""))
			continue
		} else {
			newFields = append(newFields, strings.Replace(item, "\"", "", nq/2))
		}

	}
	return newFields
}

func (c *Console) setSftpConsoleAutoComplete(registry *CommandRegistry) {
	// Get command list from registry for autocompletion
	cmdList := registry.List()

	// Add special commands that are handled in the switch statement
	cmdList = append(cmdList, "shell", "execute")

	slices.Sort(cmdList)

	// Simple autocompletion
	c.Term.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		line = strings.TrimSpace(line)
		// If TAB key is pressed and text was written
		if key == 9 && len(line) > 0 {
			newLine, newPos := autocompleteCommand(line, cmdList)
			return newLine, newPos, true
		}
		return line, pos, false
	}
}
