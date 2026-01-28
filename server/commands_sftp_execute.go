package server

import (
	"encoding/json"
	"fmt"
	"slider/pkg/instance"
	"slider/pkg/remote"
	"slider/pkg/spath"
	"slider/pkg/types"
	"strings"
)

// SftpExecuteCommand allows running the 'execute' command from within the SFTP console
// It automatically handles the current working directory.
type SftpExecuteCommand struct{}

func (c *SftpExecuteCommand) Name() string { return "execute" }
func (c *SftpExecuteCommand) Description() string {
	return "Runs a command remotely from the current directory"
}
func (c *SftpExecuteCommand) Usage() string            { return "Usage: execute [command]" }
func (c *SftpExecuteCommand) IsRemoteCompletion() bool { return true }

func (c *SftpExecuteCommand) Run(execCtx *ExecutionContext, args []string) error {
	ui := execCtx.UI()

	if len(args) < 1 {
		ui.PrintWarn("Nothing to execute\n")
		return nil
	}

	// Use SFTP Context directly from execution context
	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("failed to retrieve SFTP context")
	}

	// Get Remote Working Directory
	remoteCwd := sftpCtx.GetRemoteCwd()

	// Command in Session format
	cmdBytes, err := json.Marshal(types.CustomCmd{
		Path:    spath.NormalizeToSystemPath(remoteCwd, sftpCtx.RemoteSystem()),
		Command: strings.Join(args, " "),
	})
	if err != nil {
		return fmt.Errorf("failed to marshal command: %v", err)
	}

	// Resolve the target session
	// We need to know if the current target is local or remote to invoke the right handler.
	// Since we are in an SFTP session, we can infer some of this from the session object,
	// but the `session` in context is the *connection* session (which might be a gateway).

	// We use the TargetID stored in the SFTP context to look up the Unified Session details.
	svr := execCtx.getServer()
	unifiedMap := svr.ResolveUnifiedSessions()
	uSess, ok := unifiedMap[sftpCtx.GetTargetID()]
	if !ok {
		return fmt.Errorf("target session %d not found", sftpCtx.GetTargetID())
	}
	// Cast UI to *Console
	console, ok := ui.(*Console)
	if !ok {
		return fmt.Errorf("UI is not a Console")
	}
	// Execute Command
	if uSess.GatewayID == 0 {
		// Local Execution
		// Retrieve the actual session object
		bidirSession, err := svr.GetSession(int(uSess.ActualID))
		if err != nil {
			return fmt.Errorf("session %d not found", uSess.ActualID)
		}

		var envVarList []struct{ Key, Value string }
		instanceConfig := bidirSession.NewExecInstance(envVarList)

		if err := instanceConfig.ExecuteCommand(cmdBytes, console.ReadWriter); err != nil {
			ui.PrintError("%v", err)
		}
	} else {
		// Remote Execution

		// Get Gateway Session using GatewayID
		gatewaySession, sessErr := svr.GetSession(int(uSess.GatewayID))
		if sessErr != nil {
			return fmt.Errorf("gateway session %d not found", uSess.GatewayID)
		}

		// Construct Path
		target := append([]int64{}, uSess.Path...)
		target = append(target, uSess.ActualID)

		// Create Remote Connection
		remoteConn := remote.NewProxy(gatewaySession, target)

		// Create Instance Config
		instanceConfig := instance.New(&instance.Config{
			Logger:       svr.Logger,
			SessionID:    uSess.UnifiedID,
			EndpointType: instance.ExecEndpoint,
		})
		instanceConfig.SetSSHConn(remoteConn)

		if err := instanceConfig.ExecuteCommand(cmdBytes, console.ReadWriter); err != nil {
			ui.PrintError("Remote Execution Failed: %v", err)
		}
	}
	// Reset Console to ensure clean state
	ui.Reset()
	ui.Printf("\n")
	return nil
}
