package server

import (
	"errors"
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/server/remote"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console Socks Command
	socksCmd   = "socks"
	socksDesc  = "Runs a SOCKS5 server over an SSH Channel on a Session ID"
	socksUsage = "Usage: socks [flags]"
)

// SocksCommand implements the 'socks' command
type SocksCommand struct{}

func (c *SocksCommand) Name() string             { return socksCmd }
func (c *SocksCommand) Description() string      { return socksDesc }
func (c *SocksCommand) Usage() string            { return socksUsage }
func (c *SocksCommand) IsRemoteCompletion() bool { return true }
func (c *SocksCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
	ui := ctx.UI()

	socksFlags := pflag.NewFlagSet(socksCmd, pflag.ContinueOnError)
	socksFlags.SetOutput(ui.Writer())

	sSession := socksFlags.IntP("session", "s", 0, "Run a Socks5 server over an SSH Channel on a Session ID")
	sPort := socksFlags.IntP("port", "p", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill := socksFlags.IntP("kill", "k", 0, "Kill Socks5 Listener and Server on a Session ID")
	sExpose := socksFlags.BoolP("expose", "e", false, "Expose port to all interfaces")

	socksFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", socksUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", socksDesc)
		socksFlags.PrintDefaults()
	}

	if pErr := socksFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flag error: %w", pErr)
	}

	// Validate one required
	if !socksFlags.Changed("session") && !socksFlags.Changed("kill") {
		return fmt.Errorf("one of the flags --session or --kill must be set")
	}

	// Validate mutual exclusion
	if socksFlags.Changed("session") && socksFlags.Changed("kill") {
		return fmt.Errorf("flags --session and --kill cannot be used together")
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("port") {
		return fmt.Errorf("flags --kill and --port cannot be used together")
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("expose") {
		return fmt.Errorf("flags --kill and --expose cannot be used together")
	}

	sessionID := *sSession + *sKill

	var uSess UnifiedSession
	var isRemote bool

	// Resolve Unified Sessions
	unifiedMap := server.ResolveUnifiedSessions()
	if val, ok := unifiedMap[int64(sessionID)]; ok {
		uSess = val
		isRemote = uSess.OwnerID != 0
	} else {
		return fmt.Errorf("unknown session ID %d", sessionID)
	}

	if !isRemote {
		// Local Strategy
		session, err := server.getSession(int(uSess.ActualID))
		if err != nil {
			return fmt.Errorf("local session %d not found", uSess.ActualID)
		}

		if *sKill > 0 {
			if session.SocksInstance == nil || !session.SocksInstance.IsEnabled() {
				ui.PrintWarn("No SOCKS5 server running on session %d", sessionID)
				return nil
			}
			if err := session.SocksInstance.Stop(); err != nil {
				return fmt.Errorf("error stopping SOCKS5 server: %w", err)
			}
			ui.PrintSuccess("SOCKS5 server stopped on session %d", sessionID)
			return nil
		}

		if *sSession > 0 {
			if session.SocksInstance.IsEnabled() {
				if port, pErr := session.SocksInstance.GetEndpointPort(); pErr == nil {
					return fmt.Errorf("socks endpoint already running on port: %d", port)
				}
				return nil
			}
			ui.PrintInfo("Enabling Socks Endpoint in the background")

			notifier := make(chan error, 1)
			defer close(notifier)
			socksTicker := time.NewTicker(conf.EndpointTickerInterval)
			defer socksTicker.Stop()
			timeout := time.After(conf.Timeout)

			go session.socksEnable(*sPort, *sExpose, notifier)

			for {
				select {
				case nErr := <-notifier:
					if nErr != nil {
						return fmt.Errorf("endpoint error: %w", nErr)
					}
				case <-socksTicker.C:
					if session.SocksInstance != nil {
						port, portErr := session.SocksInstance.GetEndpointPort()
						if port == 0 || portErr != nil {
							continue
						}
						ui.PrintSuccess("Socks Endpoint running on port: %d", port)
						return nil
					}
				case <-timeout:
					return fmt.Errorf("socks endpoint reached timeout trying to start")
				}
			}
		}
	} else {
		// Remote Strategy
		key := fmt.Sprintf("socks:%d:%v", uSess.OwnerID, uSess.Path)
		server.remoteSessionsMutex.Lock()
		if _, ok := server.remoteSessions[key]; !ok {
			server.remoteSessions[key] = &RemoteSessionState{}
		}
		state := server.remoteSessions[key]
		server.remoteSessionsMutex.Unlock()

		if *sKill > 0 {
			if state.SocksInstance == nil || !state.SocksInstance.IsEnabled() {
				ui.PrintWarn("No SOCKS5 server running on remote session %d", sessionID)
				return nil
			}
			if err := state.SocksInstance.Stop(); err != nil {
				return fmt.Errorf("error stopping SOCKS5 server: %w", err)
			}
			// Cleanup
			server.remoteSessionsMutex.Lock()
			state.SocksInstance = nil
			server.remoteSessionsMutex.Unlock()
			ui.PrintSuccess("SOCKS5 server stopped on remote session %d", sessionID)
			return nil
		}

		if *sSession > 0 {
			if state.SocksInstance != nil && state.SocksInstance.IsEnabled() {
				if port, pErr := state.SocksInstance.GetEndpointPort(); pErr == nil {
					return fmt.Errorf("socks endpoint already running on port: %d", port)
				}
				return nil
			}

			// Setup Remote Connection
			gatewaySession, err := server.getSession(int(uSess.OwnerID))
			if err != nil {
				return fmt.Errorf("gateway session %d not found", uSess.OwnerID)
			}

			// Construct Target Path
			target := append([]int64{}, uSess.Path...)
			target = append(target, uSess.ActualID)

			remoteConn := remote.NewProxy(gatewaySession, target)

			// Configure Instance
			config := instance.New(&instance.Config{
				Logger:       server.Logger,
				SessionID:    uSess.UnifiedID, // Use UnifiedID for logging
				EndpointType: instance.SocksEndpoint,
			})
			config.SetSSHConn(remoteConn)
			config.SetExpose(*sExpose)

			ui.PrintInfo("Enabling Remote Socks Endpoint in the background")

			// Start non-blocking
			notifier := make(chan error, 1)
			defer close(notifier)
			go func() {
				if err := config.StartEndpoint(*sPort); err != nil {
					notifier <- err
				}
			}()

			server.remoteSessionsMutex.Lock()
			state.SocksInstance = config
			server.remoteSessionsMutex.Unlock()

			// Wait for startup or error
			socksTicker := time.NewTicker(conf.EndpointTickerInterval)
			defer socksTicker.Stop()
			timeout := time.After(conf.Timeout)

			for {
				select {
				case nErr := <-notifier:
					if nErr != nil {
						// Cleanup on failure
						server.remoteSessionsMutex.Lock()
						state.SocksInstance = nil
						server.remoteSessionsMutex.Unlock()
						return fmt.Errorf("failed to start remote socks: %w", nErr)
					}
				case <-socksTicker.C:
					port, pErr := config.GetEndpointPort()
					if port == 0 || pErr != nil {
						continue
					}
					ui.PrintSuccess("Remote Socks Endpoint running on port: %d Target: %s", port, target)
					return nil
				case <-timeout:
					return fmt.Errorf("remote socks endpoint reached timeout trying to start")
				}
			}
		}
	}
	return nil
}
