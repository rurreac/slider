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
	Session         *session.BidirectionalSession
	SftpClient      *sftp.Client
	RemoteInfo      interpreter.BaseInfo
	targetSessionID int64
	LatestDir       string
}

// newSftpConsoleWithInterpreter provides an interactive SFTP session
func (s *server) newSftpConsoleWithInterpreter(ui *Console, opts SftpConsoleOptions) {
	// Extract options for cleaner usage
	bSession := opts.Session
	sftpClient := opts.SftpClient
	remoteInfo := opts.RemoteInfo
	targetSessionID := opts.targetSessionID
	latestDir := opts.LatestDir

	// Since we always ensure an Interpreter at initialization, this should never happen.
	if bSession.GetPeerInfo().User == "" {
		ui.PrintError("Session interpreter not initialized, won't enter interactive")
		return
	}
	remoteInfo = bSession.GetPeerInfo()

	// Get the current directory
	localCwd, clErr := os.Getwd()
	if clErr != nil {
		localCwd = ""
		ui.PrintError("Unable to determine local directory: %v", clErr)
	}

	// Determine initial remote directory
	var remoteCwd string
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
	var err error
	if remoteCwd == "" {
		remoteCwd, err = sftpClient.Getwd()
		if err != nil {
			// Fallback to LaunchDir if Getwd fails (LaunchDir is always set and fallsback to HOME)
			remoteCwd = remoteInfo.LaunchDir
			ui.PrintWarn("Unable to determine remote directory, falling back to LaunchDir: %v", err)
		}
	}

	// Normalize the working directory to SFTP format (Unix-style paths)
	// SFTP protocol always uses Unix-style paths even for Windows servers
	if remoteCwd != "" {
		remoteCwd = spath.NormalizeToSFTPPath(remoteCwd, remoteInfo.System)
	}

	// Use target session ID if provided, otherwise use actual session ID
	if targetSessionID == 0 {
		targetSessionID = bSession.GetID()
	}

	// Keep remoteCwd in SFTP format (Unix-style) from sftpClient.Getwd()
	// Convert remoteHomeDir to SFTP format if it's in native Windows format
	remoteHomeDirSFTP := spath.NormalizeToSFTPPath(remoteInfo.HomeDir, remoteInfo.System)
	// Store SFTP format in the target interpreter for consistent usage
	if remoteHomeDirSFTP != remoteInfo.HomeDir {
		remoteInfo.HomeDir = remoteHomeDirSFTP
	}

	// Print welcome message and help info
	ui.PrintInfo("Starting interactive session")
	ui.PrintInfo("Type \"help\" for available commands")
	ui.PrintInfo("Type \"exit\" or press \"CTRL^C\" to return to Console")

	sftpCtx := &SftpCommandContext{
		sftpCli:          sftpClient,
		session:          bSession,
		localCwd:         &localCwd,
		remoteCwd:        &remoteCwd,
		localInterpreter: s.serverInterpreter,
		remoteInfo:       remoteInfo,
		targetID:         targetSessionID,
	}

	sftpRegistry := s.initSftpRegistry(bSession)

	// Persist the initial working directory to the session using the context
	sftpCtx.setCwd(remoteCwd, true)
	// Set the terminal prompt and autocomplete
	ui.Term.SetPrompt(sftpCtx.getSFTPPrompt())
	ui.setSftpConsoleAutoComplete(sftpRegistry, sftpCtx, sftpClient)

	// Replace Console History with own History for SFTP Session
	// Save current history first
	mainHistory := ui.Term.History

	// Initialize SFTP history if not already set
	// Each session gets its own history instance (not shared)
	if bSession.GetSftpHistory() == nil {
		bSession.SetSftpHistory(session.NewCustomHistory())
	}
	sftpHistory := bSession.GetSftpHistory()
	ui.Term.History = sftpHistory

	defer func() {
		// Restore main history when done
		ui.Term.History = mainHistory
	}()

	// Create SFTP execution context once before the loop
	execCtx := &ExecutionContext{
		server:       s,
		session:      bSession,
		ui:           ui,
		sftpCtx:      sftpCtx,
		sftpRegistry: sftpRegistry,
	}

	for {
		input, rErr := ui.Term.ReadLine()
		if rErr != nil {
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF and kills the terminal.
			// When this happens, we will return to the main Console
			return
		}

		// Parse command using the custom parser to handle quotes/spaces
		cmdParts := fieldsWithQuotes(input)

		if len(cmdParts) == 0 || cmdParts[0] == "" {
			continue
		}

		command := strings.ToLower(cmdParts[0])
		args := cmdParts[1:]

		// Handle local shell escape
		if strings.HasPrefix(command, "!") {
			if after, ok := strings.CutPrefix(command, "!"); ok {
				if len(after) > 0 {
					fullCommand := []string{after}
					fullCommand = append(fullCommand, args...)
					s.notConsoleCommandWithDir(fullCommand, *sftpCtx.localCwd)
					continue
				}
			}
			ui.PrintWarn("Usage: !command\n")
			continue
		}

		// Handle shell escape
		if command == "shell" {
			// Reuse the main shell command from the server registry
			eArgs := []string{"-s", fmt.Sprintf("%d", targetSessionID), "-i"}
			if err := s.commandRegistry.Execute(execCtx, "shell", eArgs); err != nil {
				ui.PrintError("Shell error: %v", err)
			}
			// Restore SFTP prompt and autocomplete
			ui.Term.SetPrompt(sftpCtx.getSFTPPrompt())
			ui.setSftpConsoleAutoComplete(sftpRegistry, sftpCtx, sftpClient)
			continue
		}
		if command == "psh" && execCtx.session.GetPeerInfo().System == "windows" {
			// Reuse the main shell command from the server registry
			eArgs := []string{"-s", fmt.Sprintf("%d", targetSessionID), "-i", "-a"}
			if err := s.commandRegistry.Execute(execCtx, "shell", eArgs); err != nil {
				ui.PrintError("Shell error: %v", err)
			}
			// Restore SFTP prompt and autocomplete
			ui.Term.SetPrompt(sftpCtx.getSFTPPrompt())
			ui.setSftpConsoleAutoComplete(sftpRegistry, sftpCtx, sftpClient)
			continue
		}

		// Process commands
		if _, ok := sftpRegistry.Get(command); ok {
			// Try to execute command from SFTP registry
			execErr := sftpRegistry.Execute(execCtx, command, args)
			if execErr != nil {
				if errors.Is(execErr, ErrExitConsole) {
					// Exit SFTP session
					return
				}
				ui.PrintError("Error: %v", execErr)
			}
			continue
		} else if command == "exit" {
			return
		}

		ui.PrintWarn("Unknown SFTP command: %s. Type 'help' for available commands.\n", command)
	}
}

func (ctx *SftpCommandContext) getSFTPPrompt() string {
	// Convert remoteCwd to display format for prompt
	displayPath := spath.NormalizeToSystemPath(*ctx.remoteCwd, ctx.remoteInfo.System)

	// Replace home directory with '~' if applicable but don't replace if home is root ("/")
	rCwd := displayPath
	if ctx.remoteInfo.HomeDir != "/" && strings.HasPrefix(*ctx.remoteCwd, ctx.remoteInfo.HomeDir) {
		// Replace SFTP format home with ~, then convert to display format
		rCwd = strings.Replace(*ctx.remoteCwd, ctx.remoteInfo.HomeDir, "~", 1)
	}

	return fmt.Sprintf(
		"\r(%s) %s@%s:%s%s ",
		escseq.CyanBoldText(fmt.Sprintf("S%d", ctx.targetID)),
		ctx.remoteInfo.User,
		ctx.remoteInfo.Hostname,
		rCwd,
		escseq.CyanBoldText("$"),
	)

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
	fCmd = append(s.serverInterpreter.ShellExecArgs, strings.Join(fCmd, " "))

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
