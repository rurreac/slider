package server

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/pflag"
)

const (
	// Console Execute Command
	executeCmd   = "execute"
	executeDesc  = "Runs a command remotely and returns the output"
	executeUsage = "Usage: execute [flags] [command]"
)

// ExecuteCommand implements the 'execute' command
type ExecuteCommand struct{}

func (c *ExecuteCommand) Name() string        { return executeCmd }
func (c *ExecuteCommand) Description() string { return executeDesc }
func (c *ExecuteCommand) Usage() string       { return executeUsage }

func (c *ExecuteCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
	ui := ctx.UI()

	executeFlags := pflag.NewFlagSet(executeCmd, pflag.ContinueOnError)
	executeFlags.SetOutput(ui.Writer())
	executeFlags.SetInterspersed(false) // Stop parsing flags after first non-flag argument

	eSession := executeFlags.IntP("session", "s", 0, "Run command passed as an argument on a session id")
	eAll := executeFlags.BoolP("all", "a", false, "Run command passed as an argument on all sessions")

	executeFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", executeUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", executeDesc)
		executeFlags.PrintDefaults()
	}

	if pErr := executeFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		ui.PrintError("Flag error: %v", pErr)
		return nil
	}

	// Validate mutual exclusion
	if executeFlags.Changed("session") && executeFlags.Changed("all") {
		ui.PrintError("flags --session and --all cannot be used together")
		return nil
	}

	// Validate one required
	if !executeFlags.Changed("session") && !executeFlags.Changed("all") {
		ui.PrintError("one of the flags --session or --all must be set")
		return nil
	}

	// Validate minimum args
	if executeFlags.NArg() < 1 {
		ui.PrintError("at least 1 argument(s) required, got %d", executeFlags.NArg())
		return nil
	}

	command := strings.Join(executeFlags.Args(), " ")

	var sessions []*Session
	if *eSession > 0 {
		session, sErr := server.getSession(*eSession)
		if sErr != nil {
			ui.PrintError("Unknown Session ID %d", *eSession)
			return nil
		}
		sessions = []*Session{session}
	}

	if *eAll {
		for _, session := range server.sessionTrack.Sessions {
			sessions = append(sessions, session)
		}
	}

	for _, session := range sessions {
		if *eAll {
			ui.PrintInfo("Executing Command on SessionID %d", session.sessionID)
		}

		var envVarList []struct{ Key, Value string }
		i := session.newExecInstance(envVarList)
		if err := i.ExecuteCommand(command, server.console.InitState); err != nil {
			ui.PrintError("%v", err)
		}
		server.console.Println("")
	}
	return nil
}
