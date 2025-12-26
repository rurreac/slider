package server

import (
	"errors"
	"fmt"
	"slider/pkg/instance"
	"slider/pkg/slog"
	"slider/server/remote"
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
		return pErr
	}

	// Validate mutual exclusion
	if executeFlags.Changed("session") && executeFlags.Changed("all") {
		return fmt.Errorf("flags --session and --all cannot be used together")
	}

	// Validate one required
	if !executeFlags.Changed("session") && !executeFlags.Changed("all") {
		return fmt.Errorf("one of the flags --session or --all must be set")
	}

	// Validate minimum args
	if executeFlags.NArg() < 1 {
		return fmt.Errorf("at least 1 argument(s) required, got %d", executeFlags.NArg())
	}

	command := strings.Join(executeFlags.Args(), " ")

	var sessions []UnifiedSession

	// Resolve Unified Sessions
	unifiedMap := server.ResolveUnifiedSessions()

	if *eSession > 0 {
		if uSess, ok := unifiedMap[int64(*eSession)]; ok {
			sessions = []UnifiedSession{uSess}
		} else {
			return fmt.Errorf("unknown session ID %d", *eSession)
		}
	} else if *eAll {
		for _, uSess := range unifiedMap {
			sessions = append(sessions, uSess)
		}
	}

	for _, uSess := range sessions {
		if *eAll {
			ui.PrintInfo("Executing Command on SessionID %d", uSess.UnifiedID)
		}

		if uSess.OwnerID == 0 {
			// Local
			session, err := server.getSession(int(uSess.ActualID))
			if err != nil {
				if !*eAll {
					return fmt.Errorf("session %d not found", uSess.UnifiedID)
				}
				continue
			}

			var envVarList []struct{ Key, Value string }
			i := session.newExecInstance(envVarList)
			if err := i.ExecuteCommand(command, server.console.InitState); err != nil {
				if !*eAll {
					return fmt.Errorf("execution error: %w", err)
				}
				ui.PrintError("%v", err)
			}
		} else {
			// Remote
			if err := c.handleRemoteExecute(server, uSess, command, ui); err != nil {
				if !*eAll {
					return fmt.Errorf("remote execution error: %w", err)
				}
				ui.PrintError("Remote Execution Failed on %d: %v", uSess.UnifiedID, err)
			}
		}
		server.console.Println("")
	}
	return nil
}

func (c *ExecuteCommand) handleRemoteExecute(s *server, uSess UnifiedSession, command string, _ UserInterface) error {
	// 1. Get Gateway Session
	gatewaySession, sessErr := s.getSession(int(uSess.OwnerID))
	if sessErr != nil {
		return fmt.Errorf("gateway session %d not found", uSess.OwnerID)
	}

	// 2. Construct Path
	target := append([]int64{}, uSess.Path...)
	target = append(target, uSess.ActualID)

	s.InfoWith("Executing Remote Command",
		slog.F("target_unified_id", uSess.UnifiedID),
		slog.F("target_path", target))

	// 3. Create Remote Connection
	remoteConn := remote.NewProxy(gatewaySession, target)

	// 4. Create Instance Config
	config := instance.New(&instance.Config{
		Logger:       s.Logger,
		SessionID:    uSess.UnifiedID,
		EndpointType: instance.ExecEndpoint,
	})
	config.SetSSHConn(remoteConn)
	// We don't know remote interpreter settings, so default to false?
	config.SetPtyOn(false)
	// config.SetEnvVarList? None for now.

	// 5. Execute
	if err := config.ExecuteCommand(command, s.console.InitState); err != nil {
		return err
	}
	s.console.Println("")
	return nil
}
