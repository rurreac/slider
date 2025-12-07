package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slider/pkg/conf"
	"time"

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
	*Session
	port      int
	tlsConfig *tls.Config
	ui        UserInterface
}

func (c *ShellCommand) Name() string        { return shellCmd }
func (c *ShellCommand) Description() string { return shellDesc }
func (c *ShellCommand) Usage() string       { return shellUsage }

func (c *ShellCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
	ui := ctx.UI()

	shellFlags := pflag.NewFlagSet(shellCmd, pflag.ContinueOnError)
	shellFlags.SetOutput(ui.Writer())

	sSession := shellFlags.IntP("session", "s", 0, "Target Session ID for the shell")
	sPort := shellFlags.IntP("port", "p", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill := shellFlags.IntP("kill", "k", 0, "Kill Shell Listener and Server on a Session ID")
	sInteractive := shellFlags.BoolP("interactive", "i", false, "Interactive mode, enters shell directly. Always TLS")
	sTls := shellFlags.BoolP("tls", "t", false, "Enable TLS for the Shell")
	sExpose := shellFlags.BoolP("expose", "e", false, "Expose port to all interfaces")

	shellFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", shellUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", shellDesc)
		shellFlags.PrintDefaults()
	}

	if pErr := shellFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
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

	var session *Session
	var sessErr error
	sessionID := *sSession + *sKill
	session, sessErr = server.getSession(sessionID)
	if sessErr != nil {
		return fmt.Errorf("unknown session ID %d", sessionID)
	}

	if *sKill > 0 {
		if session.ShellInstance.IsEnabled() {
			if err := session.ShellInstance.Stop(); err != nil {
				return fmt.Errorf("error stopping shell server: %w", err)
			}
			ui.PrintSuccess("Shell Endpoint gracefully stopped")
			return nil
		}
		ui.PrintInfo("No Shell Server on Session ID %d", *sKill)
		return nil
	}

	if *sSession > 0 {
		if session.ShellInstance.IsEnabled() {
			if port, pErr := session.ShellInstance.GetEndpointPort(); pErr == nil {
				return fmt.Errorf("shell endpoint already running on port: %d", port)
			}
			return nil
		}

		if *sInteractive {
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

		go session.shellEnable(*sPort, *sExpose, *sInteractive, *sTls, notifier)

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
				port, sErr := session.ShellInstance.GetEndpointPort()
				if port == 0 || sErr != nil {
					fmt.Printf(".")
					continue
				}
				ui.PrintSuccess("Shell Endpoint running on port: %d", port)
				if *sInteractive {
					tlsConfig, ccErr := server.NewClientTlsConfig()
					if ccErr != nil {
						return fmt.Errorf("failed to create client TLS certificate: %w", ccErr)
					}
					// Cast UI to *Console
					console, ok := ui.(*Console)
					if !ok {
						return fmt.Errorf("UI is not a Console")
					}
					interactiveConf := &InteractiveConsole{
						Console:   console,
						Session:   session,
						port:      port,
						tlsConfig: tlsConfig,
						ui:        ui,
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

	// When Shell is interactive, we want it to stop once we are done
	defer func() {
		if ssErr := ic.ShellInstance.Stop(); ssErr != nil {
			ic.ui.PrintDebug("Failed to stop shell session: %v", ssErr)
		}
		ic.ui.PrintInfo("Shell Endpoint gracefully stopped\n")
	}()

	conn, dErr = tls.Dial(
		"tcp",
		fmt.Sprintf("127.0.0.1:%d", ic.port),
		ic.tlsConfig,
	)
	if dErr != nil {
		return fmt.Errorf("failed to bind to port %d - %w", ic.port, dErr)
	}
	ic.ui.PrintInfo("Authenticated with mTLS")

	// If session doesn't support PTY revert Raw Terminal
	if !ic.IsPtyOn() {
		ic.ui.PrintWarn("Client does not support PTY")
		ic.ui.PrintWarn("Pressing CTR^C will interrupt the shell")

		// Only revert raw mode if we are on the local console (Stdin is a terminal)
		if term.IsTerminal(int(os.Stdin.Fd())) {
			conState, _ := term.GetState(int(os.Stdin.Fd()))
			if rErr := term.Restore(int(os.Stdin.Fd()), ic.InitState); rErr != nil {
				return fmt.Errorf("failed to revert console state, aborting to avoid inconsistent shell")
			}
			defer func() { _ = term.Restore(int(os.Stdin.Fd()), conState) }()
		}

		// Capture interrupt signals and close the connection cause this terminal doesn't know how to handle them
		go ic.CaptureInterrupts(conn)
	}

	// Clear screen (Windows Command Prompt already does that)
	if string(ic.clientInterpreter.System) != "windows" || !ic.clientInterpreter.PtyOn {
		ic.clearScreen()
	}

	// Use the Console's ReadWriter for I/O
	go func() {
		_, _ = io.Copy(ic.ReadWriter, conn)
		ic.ui.PrintWarn("Press ENTER until get back to console")
	}()
	_, _ = io.Copy(conn, ic.ReadWriter)
	return nil
}
