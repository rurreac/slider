package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"slider/pkg/completion"
	"slider/pkg/escseq"
	"slider/pkg/interpreter"
	"slider/pkg/spath"
	"strings"

	"github.com/pkg/sftp"
)

// newSftpConsoleWithInterpreter provides an interactive SFTP session with optional interpreter override
func (s *server) newSftpConsoleWithInterpreter(ui *Console, session *Session, sftpClient *sftp.Client, remoteInterpreter *interpreter.Interpreter, displaySessionID int64) {
	// Get the current directory
	localCwd, clErr := os.Getwd()
	if clErr != nil {
		localCwd = ""
		ui.PrintError("Unable to determine local directory: %v", clErr)
	}
	// Get the current remote directory for prompt
	remoteCwd, crErr := sftpClient.Getwd()
	if crErr != nil {
		remoteCwd = ""
		ui.PrintError("Unable to determine remote directory: %v", crErr)
	}

	// Use provided interpreter or fall back to session's interpreter
	var targetInterpreter *interpreter.Interpreter
	if remoteInterpreter != nil {
		targetInterpreter = remoteInterpreter
	} else {
		// Since we always ensure an Interpreter at initialization, this should never happen.
		if session.clientInterpreter == nil {
			ui.PrintError("Session interpreter not initialized, won't enter interactive")
			return
		}
		targetInterpreter = session.clientInterpreter
	}

	remoteHomeDir := targetInterpreter.HomeDir
	remoteSystem := strings.ToLower(targetInterpreter.System)
	remoteUser := strings.ToLower(targetInterpreter.User)
	renameHostname := strings.ToLower(targetInterpreter.Hostname)

	// Use display session ID if provided, otherwise use actual session ID
	sessionIDForPrompt := displaySessionID
	if sessionIDForPrompt == 0 {
		sessionIDForPrompt = session.sessionID
	}

	// Keep remoteCwd in SFTP format (Unix-style) from sftpClient.Getwd()
	// Convert remoteHomeDir to SFTP format if it's in native Windows format
	remoteHomeDirSFTP := remoteHomeDir
	if remoteSystem == "windows" && strings.Contains(remoteHomeDir, "\\") {
		// Convert native Windows path to SFTP format: C:\Users\user → /C:/Users/user
		// Only convert if it contains backslashes (native format)
		remoteHomeDirSFTP = "/" + strings.ReplaceAll(remoteHomeDir, "\\", "/")
		// Store SFTP format in the target interpreter for consistent usage
		targetInterpreter.HomeDir = remoteHomeDirSFTP
	} else if remoteSystem == "windows" && !strings.HasPrefix(remoteHomeDir, "/") && remoteHomeDir != "/" {
		// Handle case where Windows path uses forward slashes but isn't in SFTP format: C:/Users/user → /C:/Users/user
		remoteHomeDirSFTP = "/" + remoteHomeDir
		targetInterpreter.HomeDir = remoteHomeDirSFTP
	}
	// If already in SFTP format (starts with /) or Unix system, use as-is

	// Define SFTP prompt
	sftpPrompt := func() string {
		// Convert remoteCwd to display format for prompt
		displayPath := spath.SFTPPathForDisplay(remoteCwd, remoteSystem)

		// Replace home directory with ~ if applicable
		// Don't replace if home is root ("/") as that's not a real user home
		rCwd := displayPath
		if remoteHomeDirSFTP != "/" && strings.HasPrefix(remoteCwd, remoteHomeDirSFTP) {
			// Replace SFTP format home with ~, then convert to display format
			rCwd = strings.Replace(remoteCwd, remoteHomeDirSFTP, "~", 1)

			if remoteSystem == "windows" && rCwd != "~" {
				// Convert the remaining path to Windows format
				rCwd = strings.ReplaceAll(rCwd, "/", "\\")
			}
		}

		return fmt.Sprintf(
			"\r(%s) %s@%s:%s%s ",
			escseq.CyanBoldText(fmt.Sprintf("S%d", sessionIDForPrompt)),
			remoteUser,
			renameHostname,
			rCwd,
			escseq.CyanBoldText("$"),
		)

	}

	// Print welcome message and help info
	ui.PrintInfo("Starting interactive session")
	ui.PrintInfo("Type \"help\" for available commands")
	ui.PrintInfo("Type \"exit\" or press \"CTRL^C\" to return to Console")

	// Initialize SFTP command registry with the target interpreter
	s.initSftpRegistryWithInterpreter(session, sftpClient, &remoteCwd, &localCwd, targetInterpreter)

	// Set the terminal prompt and autocomplete
	ui.Term.SetPrompt(sftpPrompt())
	ui.setSftpConsoleAutoComplete(session.sftpCommandRegistry, session.sftpContext, sftpClient)

	// Replace Console History with own History for SFTP Session
	// Save current history first
	mainHistory := ui.Term.History
	ui.Term.History = session.SftpHistory

	defer func() {
		// Restore main history when done
		ui.Term.History = mainHistory
	}()

	for {
		input, rErr := ui.Term.ReadLine()
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

		// Check for exit
		if cmdParts[0] == "exit" {
			return
		}

		command := strings.ToLower(cmdParts[0])
		args := cmdParts[1:]

		// Create execution context
		ctx := &ExecutionContext{
			server:  s,
			session: session,
			ui:      ui,
		}

		// Process commands
		switch command {
		case "shell":
			eArgs := []string{"-s", fmt.Sprintf("%d", session.sessionID), "-i"}
			_ = s.commandRegistry.Execute(ctx, "shell", eArgs)
		case "execute":
			if len(args) < 1 {
				ui.PrintWarn("Nothing to execute\n")
				continue
			}
			// Prepend cd command to execute from remoteCwd
			commandStr := strings.Join(args, " ")
			commandWithCd := fmt.Sprintf("cd %s && %s", remoteCwd, commandStr)
			eArgs := []string{"-s", fmt.Sprintf("%d", session.sessionID), commandWithCd}
			_ = s.commandRegistry.Execute(ctx, "execute", eArgs)
		default:
			// This is meant to be a command to execute locally
			if after, ok := strings.CutPrefix(command, "!"); ok {
				if len(after) > 0 {
					fullCommand := []string{after}
					fullCommand = append(fullCommand, args...)
					s.notConsoleCommandWithDir(fullCommand, localCwd)
					continue
				}
			}

			// Try to execute command from SFTP registry
			err := session.sftpCommandRegistry.Execute(ctx, command, args)
			if err != nil {
				if errors.Is(err, ErrExitConsole) {
					// Exit SFTP session
					return
				}
				ui.PrintError("Error: %v", err)
			}
			ui.Term.SetPrompt(sftpPrompt())
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

// newSftpConsole is a backwards-compatible wrapper for newSftpConsoleWithInterpreter
func (s *server) newSftpConsole(ui *Console, session *Session, sftpClient *sftp.Client) {
	s.newSftpConsoleWithInterpreter(ui, session, sftpClient, nil, 0)
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

func (c *Console) setSftpConsoleAutoComplete(registry *CommandRegistry, sftpCtx *SftpCommandContext, sftpClient *sftp.Client) {
	// Get command list from registry for autocompletion
	cmdList := registry.List()

	// Add special commands that are handled in the switch statement
	cmdList = append(cmdList, "shell", "execute")

	slices.Sort(cmdList)

	// Enhanced autocompletion with path support
	c.Term.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		// Only handle TAB key
		if key != 9 {
			return line, pos, false
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			return line, pos, false
		}

		// Parse the line into arguments
		args := strings.Fields(line)
		if len(args) == 0 {
			return line, pos, false
		}

		// First word: complete command names
		if len(args) == 1 && !strings.HasSuffix(line, " ") {
			newLine, newPos := autocompleteCommand(line, cmdList)
			return newLine, newPos, true
		}

		// For subsequent arguments, try path completion
		commandName := args[0]

		// Commands that take path arguments
		cmd, ok := registry.Get(commandName)
		if !ok {
			return line, pos, false
		}

		// Get the current argument being completed
		currentArg := ""
		if !strings.HasSuffix(line, " ") {
			// Still typing the last argument
			currentArg = args[len(args)-1]
		}

		var matches []string
		var commonPrefix string
		var err error
		var system string
		var homeDir string

		if cmd.IsRemoteCompletion() {
			// Remote path completion
			remoteCwd := sftpCtx.getCwd(true)
			system = sftpCtx.getContextSystem(true)
			homeDir = sftpCtx.getContextHomeDir(true)

			completer := completion.NewRemotePathCompleter(sftpClient)
			matches, commonPrefix, err = completer.Complete(currentArg, remoteCwd, system, homeDir)
		} else {
			// Local path completion
			localCwd := sftpCtx.getCwd(false)
			system = sftpCtx.getContextSystem(false)
			homeDir = sftpCtx.getContextHomeDir(false)

			completer := completion.NewLocalPathCompleter()
			matches, commonPrefix, err = completer.Complete(currentArg, localCwd, system, homeDir)
		}

		if err != nil || len(matches) == 0 {
			// No matches, return original line
			return line, pos, false
		}

		// Build the full completed path by combining the directory part with the completion
		completedPath := buildCompletedPath(currentArg, commonPrefix, system, homeDir)

		// Build new line with completion
		newLine := buildCompletedLine(line, currentArg, completedPath, strings.HasSuffix(line, " "))

		return newLine, len(newLine), true
	}
}
