package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/remote"
	"slider/pkg/session"
	"slider/pkg/sio"
	"slider/pkg/types"

	"github.com/spf13/pflag"
	"golang.org/x/term"
)

const (
	// Console Shell Command
	shellCmd   = "shell"
	shellDesc  = "Binds to a client Shell"
	shellUsage = "Usage: shell [flags]"
)

// ShellCommand implements the 'shell' command
type ShellCommand struct{}

type InteractiveConsole struct {
	*Console
	*session.BidirectionalSession
	port         int
	tlsConfig    *tls.Config
	ui           UserInterface
	targetSystem string
}

func (c *ShellCommand) Name() string             { return shellCmd }
func (c *ShellCommand) Description() string      { return shellDesc }
func (c *ShellCommand) Usage() string            { return shellUsage }
func (c *ShellCommand) IsRemoteCompletion() bool { return false }
func (c *ShellCommand) Run(ctx *ExecutionContext, args []string) error {
	svr := ctx.getServer()
	ui := ctx.UI()

	shellFlags := pflag.NewFlagSet(shellCmd, pflag.ContinueOnError)
	shellFlags.SetOutput(ui.Writer())

	sSession := shellFlags.IntP("session", "s", 0, "Target Session ID for the shell")
	sPort := shellFlags.IntP("port", "p", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill := shellFlags.IntP("kill", "k", 0, "Kill Shell Listener and Server on a Session ID")
	sInteractive := shellFlags.BoolP("interactive", "i", false, "Interactive mode, enters shell directly. Always TLS")
	sTls := shellFlags.BoolP("tls", "t", false, "Enable TLS for the Shell")
	sExpose := shellFlags.BoolP("expose", "e", false, "Expose port to all interfaces")
	sAltShell := shellFlags.BoolP("alt-shell", "a", false, "Use the alternate shell")

	shellFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n", shellDesc)
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", shellUsage)
		shellFlags.PrintDefaults()
		_, _ = fmt.Fprintf(ui.Writer(), "\n")
	}

	if pErr := shellFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
	}

	// Reject positional arguments
	if len(shellFlags.Args()) > 0 {
		return fmt.Errorf("shell command does not accept positional arguments")
	}

	// Validate one required
	if !shellFlags.Changed("session") && !shellFlags.Changed("kill") {
		return fmt.Errorf("one of the flags --session or --kill must be set")
	}

	// Validate mutual exclusion
	if shellFlags.Changed("session") && shellFlags.Changed("kill") {
		return fmt.Errorf("flags --session and --kill cannot be used together")
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("port") {
		return fmt.Errorf("flags --kill and --port cannot be used together")
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("interactive") {
		return fmt.Errorf("flags --kill and --interactive cannot be used together")
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("tls") {
		return fmt.Errorf("flags --kill and --tls cannot be used together")
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("expose") {
		return fmt.Errorf("flags --kill and --expose cannot be used together")
	}
	if shellFlags.Changed("interactive") && shellFlags.Changed("expose") {
		return fmt.Errorf("flags --interactive and --expose cannot be used together")
	}
	if shellFlags.Changed("interactive") && shellFlags.Changed("tls") {
		return fmt.Errorf("flags --interactive and --tls cannot be used together")
	}

	sessionID := *sSession + *sKill
	// Resolve session ID for Unified Remote support
	unifiedMap := svr.ResolveUnifiedSessions()
	uSess, ok := unifiedMap[int64(sessionID)]
	if !ok {
		return fmt.Errorf("session %d not found", sessionID)
	}

	if strings.HasPrefix(uSess.Role, "operator") {
		return fmt.Errorf("shell command not allowed against operator roles")
	}

	// REMOTE PROXY STRATEGY
	if uSess.OwnerID != 0 {
		// Handle kill flag for remote shells
		if *sKill > 0 {
			return c.handleRemoteShellKill(svr, uSess, ui, *sKill)
		}
		// Handle session flag for remote shells
		if *sSession > 0 {
			return c.handleRemoteShell(svr, uSess, ui, *sPort, *sInteractive, *sTls, *sExpose, *sAltShell)
		}
	}

	// LOCAL STRATEGY
	// Map UnifiedID back to ActualID for local lookup
	sessionID = int(uSess.ActualID)
	sess, err := svr.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("unknown session ID %d", sessionID)
	}

	if *sKill > 0 {
		if sess.GetShellInstance().IsEnabled() {
			if err := sess.GetShellInstance().Stop(); err != nil {
				return fmt.Errorf("error stopping shell server: %w", err)
			}
			ui.PrintSuccess("Shell Endpoint gracefully stopped")
			return nil
		}
		ui.PrintInfo("No Shell Server on Session ID %d", *sKill)
		return nil
	}

	if *sSession > 0 {
		if sess.GetShellInstance().IsEnabled() {
			if port, pErr := sess.GetShellInstance().GetEndpointPort(); pErr == nil {
				return fmt.Errorf("shell endpoint already running on port: %d", port)
			}
			return nil
		}

		if *sInteractive {
			// To avoid uncontrollable or unpaired behavior across OS, interactive shell won't be allowed
			// if the client does not support PTY.
			// Reasons:
			// - On *nix systems we can control Interrupts using signals to safely return to Console
			// - Old Windows don't support syscall interrupts
			if !sess.IsPtyOn() {
				return fmt.Errorf("target does not support shell in interactive mode")
			}
			ui.PrintInfo("Enabling Interactive Shell Endpoint in the background")
			*sTls = true
		} else {
			ui.PrintInfo("Enabling Shell Endpoint in the background")
		}

		// Receive Errors from Endpoint
		notifier := make(chan error, 1)
		defer close(notifier)
		// Give some time to check
		shellTicker := time.NewTicker(conf.EndpointTickerInterval)
		defer shellTicker.Stop()
		timeout := time.After(conf.Timeout)

		// Capture current terminal size from console UI
		width, height := 80, 24
		if console, ok := ui.(*Console); ok {
			if rw, ok := console.ReadWriter.(interface{ Fd() uintptr }); ok {
				if w, h, err := term.GetSize(int(rw.Fd())); err == nil {
					width, height = w, h
				}
			}
		}
		// Set initial terminal size on the session so the shell endpoint can use it
		sess.SetInitTermSize(types.TermDimensions{Width: uint32(width), Height: uint32(height)})

		// Need to figure out a way to better use that error if needed
		go func() {
			_ = sess.EnableShell(*sPort, *sExpose, *sTls, *sInteractive, *sAltShell, notifier)
		}()

		for {
			// Priority check: always check notifier first
			select {
			case nErr := <-notifier:
				if nErr != nil {
					return fmt.Errorf("endpoint error: %w", nErr)
				}
			default:
				// Non-blocking, fall through
			}

			// Then check ticker and timeout
			select {
			case <-shellTicker.C:
				port, sErr := sess.GetShellInstance().GetEndpointPort()
				if port == 0 || sErr != nil {
					ui.FlatPrintf(".")
					continue
				}
				ui.PrintSuccess("Shell Endpoint running on port: %d", port)
				if *sInteractive {
					tlsConfig, ccErr := svr.NewClientTlsConfig()
					if ccErr != nil {
						return fmt.Errorf("failed to create client TLS certificate: %w", ccErr)
					}
					// Cast UI to *Console
					console, ok := ui.(*Console)
					if !ok {
						return fmt.Errorf("UI is not a Console")
					}
					interactiveConf := &InteractiveConsole{
						Console:              console,
						BidirectionalSession: sess,
						port:                 port,
						tlsConfig:            tlsConfig,
						ui:                   ui,
						targetSystem:         uSess.System,
					}
					ui.PrintInfo("Connecting to Shell...")
					if intErr := interactiveConf.Run(); intErr != nil {
						return intErr
					}
				}
				return nil
			case <-timeout:
				return fmt.Errorf("shell endpoint reached timeout trying to start")
			}
		}
	}
	return nil
}

func (s *server) NewClientTlsConfig() (*tls.Config, error) {
	if s.CertificateAuthority == nil {
		return nil, errors.New("certificate authority not initialized")
	}

	cert, ccErr := s.CertificateAuthority.CreateCertificate(false)
	if ccErr != nil {
		return nil, ccErr
	}

	tlsConfig := s.CertificateAuthority.GetTLSClientConfig(cert)
	return tlsConfig, nil
}

func (ic *InteractiveConsole) Run() error {
	var conn net.Conn
	var dErr error

	conn, dErr = tls.Dial(
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", ic.port),
		ic.tlsConfig,
	)
	if dErr != nil {
		return fmt.Errorf("failed to bind to port %d - %w", ic.port, dErr)
	}
	defer func() { _ = conn.Close() }()

	// When Shell is interactive, we want it to stop once we are done
	// Only stop after a successful connection
	defer func() {
		if ssErr := ic.GetShellInstance().Stop(); ssErr != nil {
			ic.ui.PrintDebug("Failed to stop shell session: %v", ssErr)
		}
		ic.ui.PrintInfo("Shell Endpoint gracefully stopped\n")
	}()

	ic.ui.PrintSuccess("Authenticated with mTLS")
	ic.ui.CenterScreen()

	// Signal channel to stop stdin reader when the connection errors/closes
	done := make(chan struct{})

	// Handle resize events from the console
	if ic.ResizeChan != nil {
		go func() {
			for {
				select {
				case <-done:
					return
				case size := <-ic.ResizeChan:
					if si := ic.GetShellInstance(); si != nil && si.IsEnabled() {
						si.Resize(size.Width, size.Height)
					}
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Remote -> Local: copy from connection to stdout
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ic.ReadWriter, conn)
		// Signal stdin reader to stop
		close(done)
	}()

	// Local -> Remote: cancellable stdin copy using select(2)
	go func() {
		defer wg.Done()
		sio.CopyInteractiveCancellable(conn, ic.ReadWriter, done)
	}()

	wg.Wait()
	// Reset Console to ensure clean state
	ic.ui.Reset()
	return nil
}

// handleRemoteShellKill handles killing a remote shell endpoint
func (c *ShellCommand) handleRemoteShellKill(s *server, uSess UnifiedSession, ui UserInterface, killSessionID int) error {
	key := fmt.Sprintf("shell:%d:%v", uSess.OwnerID, uSess.Path)

	s.remoteSessionsMutex.Lock()
	state, exists := s.remoteSessions[key]
	s.remoteSessionsMutex.Unlock()

	if !exists || state.ShellInstance == nil || !state.ShellInstance.IsEnabled() {
		ui.PrintInfo("No Shell Server on Session ID %d", killSessionID)
		return nil
	}

	if err := state.ShellInstance.Stop(); err != nil {
		return fmt.Errorf("error stopping shell server: %w", err)
	}

	// Clean up the tracking
	s.remoteSessionsMutex.Lock()
	if state.SocksInstance == nil && state.SSHInstance == nil {
		// No other instances, remove the entry entirely
		delete(s.remoteSessions, key)
	} else {
		// Keep the entry but nil out the shell instance
		state.ShellInstance = nil
	}
	s.remoteSessionsMutex.Unlock()

	ui.PrintSuccess("Shell Endpoint gracefully stopped")
	return nil
}

// createRemoteShellInstance creates a virtual shell instance for remote sessions
func (c *ShellCommand) createRemoteShellInstance(s *server, uSess UnifiedSession, proxy *remote.Proxy) *instance.Config {
	remoteShellInstance := instance.New(&instance.Config{
		Logger:               s.Logger,
		SessionID:            uSess.UnifiedID,
		EndpointType:         instance.ShellEndpoint,
		CertificateAuthority: s.CertificateAuthority,
	})

	// Set the proxy as the SSH connection (it implements ChannelOpener)
	remoteShellInstance.SetSSHConn(proxy)

	return remoteShellInstance
}

// enableRemoteShell starts the shell endpoint for remote sessions
func (c *ShellCommand) enableRemoteShell(shellInstance *instance.Config, port int, expose bool, tlsOn bool, interactiveOn bool, notifier chan error) {
	shellInstance.SetExpose(expose)

	if tlsOn {
		shellInstance.SetTLSOn(tlsOn)
		if interactiveOn {
			shellInstance.SetInteractiveOn(interactiveOn)
			defer shellInstance.SetInteractiveOn(false)
		}
		if err := shellInstance.StartTLSEndpoint(port); err != nil {
			if notifier != nil {
				notifier <- err
			}
		}
	} else {
		if err := shellInstance.StartEndpoint(port); err != nil {
			if notifier != nil {
				notifier <- err
			}
		}
	}
}

// runRemoteInteractiveShell handles interactive shell connections for remote sessions
func (c *ShellCommand) runRemoteInteractiveShell(ic *InteractiveConsole, shellInstance *instance.Config) error {
	var conn net.Conn
	var dErr error

	conn, dErr = tls.Dial(
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", ic.port),
		ic.tlsConfig,
	)
	if dErr != nil {
		return fmt.Errorf("failed to bind to port %d - %w", ic.port, dErr)
	}
	defer func() { _ = conn.Close() }()

	// When Shell is interactive, we want it to stop once we are done
	// Only stop after successful connection
	defer func() {
		if ssErr := shellInstance.Stop(); ssErr != nil {
			ic.ui.PrintDebug("Failed to stop shell session: %v", ssErr)
		}
		ic.ui.PrintInfo("Shell Endpoint gracefully stopped\n")
	}()

	ic.ui.PrintSuccess("Authenticated with mTLS")
	ic.ui.CenterScreen()

	// Signal channel to stop stdin reader when the connection errors/closes
	done := make(chan struct{})

	// Handle resize events from the console
	if ic.ResizeChan != nil {
		go func() {
			for {
				select {
				case <-done:
					return
				case size := <-ic.ResizeChan:
					if shellInstance != nil && shellInstance.IsEnabled() {
						shellInstance.Resize(size.Width, size.Height)
					}
				}
			}
		}()
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Remote -> Local: copy from connection to stdout
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ic.ReadWriter, conn)
		// Signal stdin reader to stop
		close(done)
	}()

	// Local -> Remote: cancellable stdin copy using select(2)
	go func() {
		defer wg.Done()
		sio.CopyInteractiveCancellable(conn, ic.ReadWriter, done)
	}()

	wg.Wait()
	// Reset Console to ensure clean state
	ic.ui.Reset()
	return nil
}

// handleRemoteShell uses a unified approach with local sessions via remote.Proxy
func (c *ShellCommand) handleRemoteShell(s *server, uSess UnifiedSession, ui UserInterface, port int, interactive bool, tlsOn bool, expose bool, useAltShell bool) error {
	// Create tracking key for this remote session
	key := fmt.Sprintf("shell:%d:%v", uSess.OwnerID, uSess.Path)

	// Check if shell endpoint already exists for this remote session
	s.remoteSessionsMutex.Lock()
	if _, ok := s.remoteSessions[key]; !ok {
		s.remoteSessions[key] = &RemoteSessionState{}
	}
	state := s.remoteSessions[key]
	s.remoteSessionsMutex.Unlock()

	// Check if shell is already enabled
	if state.ShellInstance != nil && state.ShellInstance.IsEnabled() {
		if existingPort, pErr := state.ShellInstance.GetEndpointPort(); pErr == nil {
			return fmt.Errorf("shell endpoint already running on port: %d", existingPort)
		}
	}

	// Get Gateway Session
	gatewaySession, sessErr := s.GetSession(int(uSess.OwnerID))
	if sessErr != nil {
		return fmt.Errorf("gateway session %d not found (disconnected?)", uSess.OwnerID)
	}

	// Construct Target Path for slider-connect
	target := append([]int64{}, uSess.Path...)
	target = append(target, uSess.ActualID)

	// Create a remote proxy that implements ChannelOpener
	proxy := remote.NewProxy(gatewaySession, target)

	// Create a virtual shell instance using the proxy
	remoteShellInstance := c.createRemoteShellInstance(s, uSess, proxy)

	// Track the instance
	s.remoteSessionsMutex.Lock()
	state.ShellInstance = remoteShellInstance
	s.remoteSessionsMutex.Unlock()

	// Handle interactive mode using the same path as local sessions
	if interactive {
		// Capture current terminal size from console UI
		width, height := 80, 24
		if console, ok := ui.(*Console); ok {
			if rw, ok := console.ReadWriter.(interface{ Fd() uintptr }); ok {
				if w, h, err := term.GetSize(int(rw.Fd())); err == nil {
					width, height = w, h
				}
			}
		}

		// Virtual instances don't have a source session we can set dimensions on easily
		// to propagate to the Service. We need to set it on the remoteShellInstance directly.
		remoteShellInstance.SetInitTermSize(types.TermDimensions{Width: uint32(width), Height: uint32(height)})
		remoteShellInstance.SetUseAltShell(useAltShell)

		ui.PrintInfo("Enabling Interactive Shell Endpoint in the background")
		tlsOn = true
	} else {
		ui.PrintInfo("Enabling Shell Endpoint in the background")
	}

	// 10. Use the same endpoint creation logic as local sessions
	// Receive Errors from Endpoint
	notifier := make(chan error, 1)
	defer close(notifier)

	// Give some time to check
	shellTicker := time.NewTicker(conf.EndpointTickerInterval)
	defer shellTicker.Stop()
	timeout := time.After(conf.Timeout)

	go c.enableRemoteShell(remoteShellInstance, port, expose, tlsOn, interactive, notifier)

	for {
		// Priority check: always check notifier first
		select {
		case nErr := <-notifier:
			if nErr != nil {
				return fmt.Errorf("endpoint error: %w", nErr)
			}
		default:
			// Non-blocking, fall through
		}

		// Then check ticker and timeout
		select {
		case <-shellTicker.C:
			actualPort, sErr := remoteShellInstance.GetEndpointPort()
			if actualPort == 0 || sErr != nil {
				ui.FlatPrintf(".")
				continue
			}
			ui.PrintSuccess("Shell Endpoint running on port: %d", actualPort)

			if interactive {
				tlsConfig, ccErr := s.NewClientTlsConfig()
				if ccErr != nil {
					return fmt.Errorf("failed to create client TLS certificate: %w", ccErr)
				}
				// Cast UI to *Console
				console, ok := ui.(*Console)
				if !ok {
					return fmt.Errorf("UI is not a Console")
				}
				interactiveConf := &InteractiveConsole{
					Console:              console,
					BidirectionalSession: nil, // Not needed for remote
					port:                 actualPort,
					tlsConfig:            tlsConfig,
					ui:                   ui,
					targetSystem:         uSess.System,
				}
				ui.PrintInfo("Connecting to Shell...")

				if intErr := c.runRemoteInteractiveShell(interactiveConf, remoteShellInstance); intErr != nil {
					return intErr
				}
			}
			return nil
		case <-timeout:
			return fmt.Errorf("shell endpoint reached timeout trying to start")
		}
	}
}
