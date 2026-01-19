package server

import (
	"errors"
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/instance/socks"
	"slider/pkg/remote"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console Socks Command
	socksCmd   = "socks"
	socksDesc  = "Manages SOCKS5 servers (local and session-based)"
	socksUsage = "Usage: socks [flags]"
)

// SocksCommand implements the 'socks' command
type SocksCommand struct{}

func (c *SocksCommand) Name() string             { return socksCmd }
func (c *SocksCommand) Description() string      { return socksDesc }
func (c *SocksCommand) Usage() string            { return socksUsage }
func (c *SocksCommand) IsRemoteCompletion() bool { return false }
func (c *SocksCommand) Run(ctx *ExecutionContext, args []string) error {
	svr := ctx.getServer()
	ui := ctx.UI()

	socksFlags := pflag.NewFlagSet(socksCmd, pflag.ContinueOnError)
	socksFlags.SetOutput(ui.Writer())

	sSession := socksFlags.IntP("session", "s", 0, "Run a Socks5 server over an SSH Channel on a Session ID")
	sPort := socksFlags.IntP("port", "p", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill := socksFlags.IntP("kill", "k", 0, "Kill Socks5 server by port number")
	sExpose := socksFlags.BoolP("expose", "e", false, "Expose port to all interfaces")
	sLocal := socksFlags.BoolP("local", "l", false, "Create a local SOCKS5 server (without a session)")

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

	// Listing mode - no flags provided
	if !socksFlags.Changed("session") && !socksFlags.Changed("kill") && !socksFlags.Changed("local") {
		return listSocksSessions(svr, ui)
	}

	// Validate mutual exclusion
	if socksFlags.Changed("session") && socksFlags.Changed("local") {
		return fmt.Errorf("flags --session and --local cannot be used together")
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("session") {
		return fmt.Errorf("flags --kill and --session cannot be used together")
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("local") {
		return fmt.Errorf("flags --kill and --local cannot be used together")
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("expose") {
		return fmt.Errorf("flags --kill and --expose cannot be used together")
	}

	// Kill operation
	if *sKill > 0 {
		return killLocalSocksServer(svr, ui)
	}

	// Local SOCKS server creation
	if *sLocal {
		return createLocalSocksServer(svr, ui, *sPort, *sExpose)
	}

	// Session-based SOCKS server (existing logic)
	if *sSession > 0 {
		return createSessionSocksServer(svr, ui, *sSession, *sPort, *sExpose)
	}

	return fmt.Errorf("one of the flags --session, --local, or --kill must be set")
}

// listSocksSessions displays all active SOCKS sessions in a table
func listSocksSessions(svr *server, ui UserInterface) error {
	totalSocks := 0

	// List session-based SOCKS servers (local sessions)
	sessionList := svr.GetAllSessions()
	if len(sessionList)+svr.localSocks.port > 0 {
		tw := new(tabwriter.Writer)
		tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)

		_, _ = fmt.Fprintf(tw, "\n\tType\tID/Port\tLocal Port\t")
		_, _ = fmt.Fprintf(tw, "\n\t----\t-------\t----------\t\n")

		// Check for local SOCKS server
		svr.localSocks.mu.Lock()
		if svr.localSocks.port != 0 {
			_, _ = fmt.Fprintf(tw, "\tLOCAL\t--\t%d\t\n", svr.localSocks.port)
			totalSocks++
		}
		svr.localSocks.mu.Unlock()

		// List local session SOCKS servers
		for _, sess := range sessionList {
			if sess.GetSocksInstance() != nil && sess.GetSocksInstance().IsEnabled() {
				port, pErr := sess.GetSocksInstance().GetEndpointPort()
				if pErr != nil {
					port = 0
				}
				_, _ = fmt.Fprintf(tw, "\tSESSION\t%d\t%d\t\n", sess.GetID(), port)
				totalSocks++
			}
		}

		// List remote session SOCKS servers
		unifiedMap := svr.ResolveUnifiedSessions()
		for unifiedID, uSess := range unifiedMap {
			if uSess.OwnerID != 0 { // Remote session
				socksKey := fmt.Sprintf("socks:%d:%v", uSess.OwnerID, uSess.Path)
				svr.remoteSessionsMutex.Lock()
				if state, ok := svr.remoteSessions[socksKey]; ok {
					if state.SocksInstance != nil && state.SocksInstance.IsEnabled() {
						port, pErr := state.SocksInstance.GetEndpointPort()
						if pErr != nil {
							port = 0
						}
						_, _ = fmt.Fprintf(tw, "\tSESSION\t%d\t%d\t\n", unifiedID, port)
						totalSocks++
					}
				}
				svr.remoteSessionsMutex.Unlock()
			}
		}

		_, _ = fmt.Fprintln(tw)
		_ = tw.Flush()
	}
	ui.PrintInfo("Active SOCKS servers: %d\n", totalSocks)
	return nil
}

// killLocalSocksServer stops and removes the local SOCKS server
func killLocalSocksServer(svr *server, ui UserInterface) error {
	svr.localSocks.mu.Lock()
	if svr.localSocks.server == nil {
		svr.localSocks.mu.Unlock()
		return fmt.Errorf("no local SOCKS server running")
	}

	// Stop the server
	err := svr.localSocks.server.Stop()
	svr.localSocks.server = nil
	svr.localSocks.port = 0
	svr.localSocks.mu.Unlock()

	if err != nil {
		return fmt.Errorf("error stopping SOCKS5 server: %w", err)
	}

	ui.PrintSuccess("Local SOCKS5 server stopped")
	return nil
}

// createLocalSocksServer creates a standalone local SOCKS server
func createLocalSocksServer(svr *server, ui UserInterface, port int, expose bool) error {
	// Check if already exists
	svr.localSocks.mu.Lock()
	if svr.localSocks.port != 0 {
		existingPort := svr.localSocks.port
		svr.localSocks.mu.Unlock()
		return fmt.Errorf("local SOCKS server already running on port: %d", existingPort)
	}
	svr.localSocks.mu.Unlock()

	// Create local SOCKS server
	localSvr, err := socks.NewLocalServer(port, expose, svr.Logger)
	if err != nil {
		return err
	}

	// Store the server state
	svr.localSocks.mu.Lock()
	svr.localSocks.server = localSvr
	svr.localSocks.port = localSvr.Port()
	svr.localSocks.mu.Unlock()

	ui.PrintSuccess("Local listener started on port: %d", localSvr.Port())

	// Start the server in a goroutine
	go func() {
		// Block until stopped
		localSvr.Start()

		// Cleanup after server stops
		svr.localSocks.mu.Lock()
		svr.localSocks.server = nil
		svr.localSocks.port = 0
		svr.localSocks.mu.Unlock()
	}()

	return nil
}

// createSessionSocksServer creates a SOCKS server for a specific session
func createSessionSocksServer(svr *server, ui UserInterface, sessionID int, port int, expose bool) error {
	var uSess UnifiedSession
	var isRemote bool

	// Resolve Unified Sessions
	unifiedMap := svr.ResolveUnifiedSessions()
	if val, ok := unifiedMap[int64(sessionID)]; ok {
		if strings.HasPrefix(val.Role, "operator") {
			return fmt.Errorf("socks command not allowed against operator roles")
		}
		uSess = val
		isRemote = uSess.OwnerID != 0
	} else {
		return fmt.Errorf("unknown session ID %d", sessionID)
	}

	if !isRemote {
		// Local Strategy
		session, err := svr.GetSession(int(uSess.ActualID))
		if err != nil {
			return fmt.Errorf("local session %d not found", uSess.ActualID)
		}

		if session.GetSocksInstance().IsEnabled() {
			if port, pErr := session.GetSocksInstance().GetEndpointPort(); pErr == nil {
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

		// Need to figure out a way to better use that error if needed
		go func() { _ = session.EnableSocks(port, expose, notifier) }()

		for {
			select {
			case nErr := <-notifier:
				if nErr != nil {
					return fmt.Errorf("endpoint error: %w", nErr)
				}
			case <-socksTicker.C:
				if session.GetSocksInstance() != nil {
					port, portErr := session.GetSocksInstance().GetEndpointPort()
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
	} else {
		// Remote Strategy
		key := fmt.Sprintf("socks:%d:%v", uSess.OwnerID, uSess.Path)
		svr.remoteSessionsMutex.Lock()
		if _, ok := svr.remoteSessions[key]; !ok {
			svr.remoteSessions[key] = &RemoteSessionState{}
		}
		state := svr.remoteSessions[key]
		svr.remoteSessionsMutex.Unlock()

		if state.SocksInstance != nil && state.SocksInstance.IsEnabled() {
			if port, pErr := state.SocksInstance.GetEndpointPort(); pErr == nil {
				return fmt.Errorf("socks endpoint already running on port: %d", port)
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
			SessionID:    uSess.UnifiedID, // Use UnifiedID for logging
			EndpointType: instance.SocksEndpoint,
		})
		config.SetSSHConn(remoteConn)
		config.SetExpose(expose)

		ui.PrintInfo("Enabling Remote Socks Endpoint in the background")

		// Start non-blocking
		notifier := make(chan error, 1)
		defer close(notifier)
		go func() {
			if err := config.StartEndpoint(port); err != nil {
				notifier <- err
			}
		}()

		svr.remoteSessionsMutex.Lock()
		state.SocksInstance = config
		svr.remoteSessionsMutex.Unlock()

		// Wait for startup or error
		socksTicker := time.NewTicker(conf.EndpointTickerInterval)
		defer socksTicker.Stop()
		timeout := time.After(conf.Timeout)

		for {
			select {
			case nErr := <-notifier:
				if nErr != nil {
					// Cleanup on failure
					svr.remoteSessionsMutex.Lock()
					state.SocksInstance = nil
					svr.remoteSessionsMutex.Unlock()
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
