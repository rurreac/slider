package server

import (
	"errors"
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/remote"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console SSH Command
	sshCmd   = "ssh"
	sshDesc  = "Runs an local SSH server piped to an SSH Channel on a Session ID"
	sshUsage = "Usage: ssh [flags]"
)

// SSHCommand implements the 'ssh' command
type SSHCommand struct{}

func (c *SSHCommand) Name() string             { return sshCmd }
func (c *SSHCommand) Description() string      { return sshDesc }
func (c *SSHCommand) Usage() string            { return sshUsage }
func (c *SSHCommand) IsRemoteCompletion() bool { return false }
func (c *SSHCommand) Run(ctx *ExecutionContext, args []string) error {
	svr := ctx.getServer()
	ui := ctx.UI()

	sshFlags := pflag.NewFlagSet(sshCmd, pflag.ContinueOnError)
	sshFlags.SetOutput(ui.Writer())

	sSession := sshFlags.IntP("session", "s", 0, "Session ID to establish SSH connection with")
	sPort := sshFlags.IntP("port", "p", 0, "Local port to forward SSH connection to")
	sKill := sshFlags.IntP("kill", "k", 0, "Kill SSH port forwarding to a Session ID")
	sExpose := sshFlags.BoolP("expose", "e", false, "Expose port to all interfaces")

	sshFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", sshUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", sshDesc)
		sshFlags.PrintDefaults()
	}

	if pErr := sshFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flag error: %w", pErr)
	}

	// Validate one required
	if !sshFlags.Changed("session") && !sshFlags.Changed("kill") {
		return fmt.Errorf("one of the flags --session or --kill must be set")
	}

	// Validate mutual exclusion
	if sshFlags.Changed("session") && sshFlags.Changed("kill") {
		return fmt.Errorf("flags --session and --kill cannot be used together")
	}
	if sshFlags.Changed("kill") && sshFlags.Changed("port") {
		return fmt.Errorf("flags --kill and --port cannot be used together")
	}
	if sshFlags.Changed("kill") && sshFlags.Changed("expose") {
		return fmt.Errorf("flags --kill and --expose cannot be used together")
	}

	sessionID := *sSession + *sKill

	var uSess UnifiedSession
	var isRemote bool

	// Resolve Unified Sessions
	unifiedMap := svr.ResolveUnifiedSessions()
	if val, ok := unifiedMap[int64(sessionID)]; ok {
		uSess = val
		isRemote = uSess.OwnerID != 0
	} else {
		return fmt.Errorf("unknown session ID %d", sessionID)
	}

	if !isRemote {
		// Local Strategy
		session, sErr := svr.GetSession(int(uSess.ActualID))
		if sErr != nil {
			return fmt.Errorf("local session %d not found", uSess.ActualID)
		}

		if *sKill > 0 {
			if session.GetSSHInstance().IsEnabled() {
				if err := session.GetSSHInstance().Stop(); err != nil {
					return fmt.Errorf("error stopping SSH server: %w", err)
				}
				ui.PrintSuccess("SSH Endpoint gracefully stopped")
				return nil
			}
			ui.PrintInfo("No SSH Server on Session ID %d", *sKill)
			return nil
		}

		if *sSession > 0 {
			if session.GetSSHInstance().IsEnabled() {
				if port, pErr := session.GetSSHInstance().GetEndpointPort(); pErr == nil {
					return fmt.Errorf("ssh endpoint already running on port: %d", port)
				}
				return nil
			}
			ui.PrintInfo("Enabling SSH Endpoint in the background")

			notifier := make(chan error, 1)
			defer close(notifier)
			sshTicker := time.NewTicker(conf.EndpointTickerInterval)
			defer sshTicker.Stop()
			timeout := time.After(conf.Timeout)

			// Need to figure out a way to better use that error if needed
			go func() { _ = session.EnableSSH(*sPort, *sExpose, notifier) }()

			for {
				select {
				case nErr := <-notifier:
					if nErr != nil {
						return fmt.Errorf("endpoint error: %w", nErr)
					}
				case <-sshTicker.C:
					port, sErr := session.GetSSHInstance().GetEndpointPort()
					if port == 0 || sErr != nil {
						continue
					}
					ui.PrintSuccess("SSH Endpoint running on port: %d", port)
					return nil
				case <-timeout:
					return fmt.Errorf("ssh endpoint reached timeout trying to start")
				}
			}
		}
	} else {
		// Remote Strategy
		key := fmt.Sprintf("ssh:%d:%v", uSess.OwnerID, uSess.Path)
		svr.remoteSessionsMutex.Lock()
		if _, ok := svr.remoteSessions[key]; !ok {
			svr.remoteSessions[key] = &RemoteSessionState{}
		}
		state := svr.remoteSessions[key]
		svr.remoteSessionsMutex.Unlock()

		if *sKill > 0 {
			if state.SSHInstance == nil || !state.SSHInstance.IsEnabled() {
				ui.PrintWarn("No SSH Server running on remote session %d", sessionID)
				return nil
			}
			if err := state.SSHInstance.Stop(); err != nil {
				return fmt.Errorf("error stopping SSH server: %w", err)
			}
			// Cleanup
			svr.remoteSessionsMutex.Lock()
			state.SSHInstance = nil
			svr.remoteSessionsMutex.Unlock()
			ui.PrintSuccess("SSH Endpoint gracefully stopped on remote session %d", sessionID)
			return nil
		}

		if *sSession > 0 {
			if state.SSHInstance != nil && state.SSHInstance.IsEnabled() {
				if port, pErr := state.SSHInstance.GetEndpointPort(); pErr == nil {
					return fmt.Errorf("ssh endpoint already running on port: %d", port)
				}
				return nil
			}

			// Setup Remote Connection
			gatewaySession, err := svr.GetSession(int(uSess.OwnerID))
			if err != nil {
				return fmt.Errorf("gateway session %d not found", uSess.OwnerID)
			}

			// Construct Target Path
			target := append([]int64{}, uSess.Path...)
			target = append(target, uSess.ActualID)

			remoteConn := remote.NewProxy(gatewaySession, target)

			// Configure Instance
			config := instance.New(&instance.Config{
				Logger:       svr.Logger,
				SessionID:    uSess.UnifiedID,
				EndpointType: instance.SshEndpoint,
				ServerKey:    svr.serverKey, // Needed for SSH handshake
				// AuthOn? Server.authOn?
				AuthOn: svr.authOn,
			})
			config.SetSSHConn(remoteConn)
			config.SetExpose(*sExpose)

			ui.PrintInfo("Enabling Remote SSH Endpoint in the background")

			// Start SSH Endpoint
			notifier := make(chan error, 1)
			defer close(notifier)
			go func() {
				if err := config.StartEndpoint(*sPort); err != nil {
					notifier <- err
				}
			}()

			svr.remoteSessionsMutex.Lock()
			state.SSHInstance = config
			svr.remoteSessionsMutex.Unlock()

			// Wait for startup
			sshTicker := time.NewTicker(conf.EndpointTickerInterval)
			defer sshTicker.Stop()
			timeout := time.After(conf.Timeout)

			for {
				select {
				case nErr := <-notifier:
					if nErr != nil {
						svr.remoteSessionsMutex.Lock()
						state.SSHInstance = nil
						svr.remoteSessionsMutex.Unlock()
						return fmt.Errorf("failed to start remote ssh endpoint: %w", nErr)
					}
				case <-sshTicker.C:
					port, sErr := config.GetEndpointPort()
					if port == 0 || sErr != nil {
						continue
					}
					ui.PrintSuccess("Remote SSH Endpoint running on port: %d", port)
					return nil
				case <-timeout:
					return fmt.Errorf("remote ssh endpoint reached timeout trying to start")
				}
			}
		}
	}
	return nil
}
