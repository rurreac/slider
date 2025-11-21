package server

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/pflag"
)

// ExecuteCommand implements the 'execute' command
type ExecuteCommand struct{}

func (c *ExecuteCommand) Name() string        { return executeCmd }
func (c *ExecuteCommand) Description() string { return executeDesc }
func (c *ExecuteCommand) Usage() string       { return executeUsage }

func (c *ExecuteCommand) Run(s *server, args []string, out io.Writer) error {
	executeFlags := pflag.NewFlagSet(executeCmd, pflag.ContinueOnError)
	executeFlags.SetOutput(out)
	executeFlags.SetInterspersed(false) // Stop parsing flags after first non-flag argument

	eSession := executeFlags.IntP("session", "s", 0, "Run command passed as an argument on a session id")
	eAll := executeFlags.BoolP("all", "a", false, "Run command passed as an argument on all sessions")

	executeFlags.Usage = func() {
		fmt.Fprintf(out, "Usage: %s\n\n", executeUsage)
		fmt.Fprintf(out, "%s\n\n", executeDesc)
		executeFlags.PrintDefaults()
	}

	if pErr := executeFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return nil
	}

	// Validate mutual exclusion
	if executeFlags.Changed("session") && executeFlags.Changed("all") {
		s.console.PrintlnErrorStep("flags --session and --all cannot be used together")
		return nil
	}

	// Validate one required
	if !executeFlags.Changed("session") && !executeFlags.Changed("all") {
		s.console.PrintlnErrorStep("one of the flags --session or --all must be set")
		return nil
	}

	// Validate minimum args
	if executeFlags.NArg() < 1 {
		s.console.PrintlnErrorStep("at least 1 argument(s) required, got %d", executeFlags.NArg())
		return nil
	}

	command := strings.Join(executeFlags.Args(), " ")

	var sessions []*Session
	if *eSession > 0 {
		session, sessErr := s.getSession(*eSession)
		if sessErr != nil {
			s.console.PrintlnErrorStep("Unknown Session ID %d", *eSession)
			return nil
		}
		sessions = []*Session{session}
	}

	if *eAll {
		for _, session := range s.sessionTrack.Sessions {
			sessions = append(sessions, session)
		}
	}

	for _, session := range sessions {
		if *eAll {
			s.console.PrintlnInfo("Executing Command on SessionID %d", session.sessionID)
		}

		var envVarList []struct{ Key, Value string }

		i := session.newExecInstance(envVarList)

		if err := i.ExecuteCommand(command, s.console.InitState); err != nil {
			s.console.PrintlnErrorStep("%v", err)
		}
		s.console.Println("")
	}
	return nil
}
