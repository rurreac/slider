package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"

	"slider/pkg/completion"
	"slider/pkg/escseq"
	"slider/pkg/interpreter"
	"slider/pkg/session"
	"slider/pkg/spath"

	"github.com/pkg/sftp"
)

// SftpConsoleOptions defines configuration for starting an interactive SFTP session
type SftpConsoleOptions struct {
	Session           *session.BidirectionalSession
	SftpClient        *sftp.Client
	RemoteInterpreter *interpreter.Interpreter
	DisplaySessionID  int64
	LatestDir         string
}

// newSftpConsoleWithInterpreter provides an interactive SFTP session
func (s *server) newSftpConsoleWithInterpreter(ui *Console, opts SftpConsoleOptions) {
	// Extract options for cleaner usage
	bSession := opts.Session
	sftpClient := opts.SftpClient
	remoteInterpreter := opts.RemoteInterpreter
	displaySessionID := opts.DisplaySessionID
	latestDir := opts.LatestDir
	// Use provided interpreter or fall back to session's interpreter
	var targetInterpreter *interpreter.Interpreter
	if remoteInterpreter != nil {
		targetInterpreter = remoteInterpreter
	} else {
		// Since we always ensure an Interpreter at initialization, this should never happen.
		if bSession.GetInterpreter() == nil {
			ui.PrintError("Session interpreter not initialized, won't enter interactive")
			return
		}
		targetInterpreter = bSession.GetInterpreter()
	}

	// Get the current directory
	localCwd, clErr := os.Getwd()
	if clErr != nil {
		localCwd = ""
		ui.PrintError("Unable to determine local directory: %v", clErr)
	}

	remoteHomeDir := targetInterpreter.HomeDir
	remoteSystem := strings.ToLower(targetInterpreter.System)
	remoteUser := strings.ToLower(targetInterpreter.User)
	renameHostname := strings.ToLower(targetInterpreter.Hostname)

	// Determine initial remote directory
	var remoteCwd string
	var err error

	// Try to use the provided latest directory (history)
	if latestDir != "" {
		// Try to change to the requested directory
		// We use the sftp client to verify it exists and is accessible
		if stat, err := sftpClient.Stat(latestDir); err == nil && stat.IsDir() {
			// Success! Use the provided directory
			remoteCwd = latestDir
		} else {
			ui.PrintWarn("Could not restore working directory \"%s\" (error or not a dir): %v", latestDir, err)
			// Fallback to default behavior below
		}
	}

	// If no latest dir or it failed, use current sftp working directory
	if remoteCwd == "" {
		remoteCwd, err = sftpClient.Getwd()
		if err != nil {
			// Fallback to LaunchDir if Getwd fails (LaunchDir is always set and fallsback to HOME)
			remoteCwd = targetInterpreter.LaunchDir
			ui.PrintWarn("Unable to determine remote directory, falling back to LaunchDir: %v", err)
		}
	}

	// Normalize the working directory to SFTP format (Unix-style paths)
	// SFTP protocol always uses Unix-style paths even for Windows servers
	if remoteCwd != "" && remoteSystem == "windows" {
		// Check if the path is in raw Windows format (contains backslashes)
		if strings.Contains(remoteCwd, "\\") {
			// Convert native Windows path to SFTP format: C:\Users\user → /C:/Users/user
			remoteCwd = "/" + strings.ReplaceAll(remoteCwd, "\\", "/")
		} else if len(remoteCwd) >= 2 && remoteCwd[1] == ':' && !strings.HasPrefix(remoteCwd, "/") {
			// Handle case where Windows path uses forward slashes but isn't in SFTP format: C:/Users/user → /C:/Users/user
			remoteCwd = "/" + remoteCwd
		}
	}

	// Use display session ID if provided, otherwise use actual session ID
	sessionIDForPrompt := displaySessionID
	if sessionIDForPrompt == 0 {
		sessionIDForPrompt = bSession.GetID()
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

	// Initialize SFTP command registry with the target interpreter (initializes SFTP context as well)
	s.initSftpRegistry(bSession, sftpClient, &remoteCwd, &localCwd, targetInterpreter)

	// Persist the initial working directory to the session using the context
	if sftpCtx, ok := bSession.GetSftpContext().(*SftpCommandContext); ok {
		sftpCtx.setCwd(remoteCwd, true)
		// Set the terminal prompt and autocomplete
		ui.Term.SetPrompt(sftpPrompt())
		ui.setSftpConsoleAutoComplete(bSession.GetSftpCommandRegistry().(*CommandRegistry), sftpCtx, sftpClient)
	} else {
		// Die if we can't retrieve context
		ui.PrintError("Failed to retrieve SFTP context")
		return
	}

	// Replace Console History with own History for SFTP Session
	// Save current history first
	mainHistory := ui.Term.History

	// Initialize SFTP history if not already set
	// Each session gets its own history instance (not shared)
	if bSession.GetSftpHistory() == nil {
		bSession.SetSftpHistory(NewCustomHistory())
	}
	ui.Term.History = bSession.GetSftpHistory().(*CustomHistory)

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
			session: bSession,
			ui:      ui,
		}

		// Process commands
		switch command {
		case "shell":
			eArgs := []string{"-s", fmt.Sprintf("%d", bSession.GetID()), "-i"}
			_ = s.commandRegistry.Execute(ctx, "shell", eArgs)
		case "execute":
			if len(args) < 1 {
				ui.PrintWarn("Nothing to execute\n")
				continue
			}
			// Prepend cd command to execute from remoteCwd
			commandStr := strings.Join(args, " ")
			commandWithCd := fmt.Sprintf("cd %s && %s", remoteCwd, commandStr)
			eArgs := []string{"-s", fmt.Sprintf("%d", bSession.GetID()), commandWithCd}
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
			err := bSession.GetSftpCommandRegistry().(*CommandRegistry).Execute(ctx, command, args)
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
