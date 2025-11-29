package server

import (
	"errors"
	"fmt"
	"slider/pkg/conf"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console SSH Command
	sshCmd   = "ssh"
	sshDesc  = "Runs a Socks5 server over an SSH Channel on a Session ID"
	sshUsage = "Usage: ssh [flags]"
)

// SSHCommand implements the 'ssh' command
type SSHCommand struct{}

func (c *SSHCommand) Name() string        { return sshCmd }
func (c *SSHCommand) Description() string { return sshDesc }
func (c *SSHCommand) Usage() string       { return sshUsage }

func (c *SSHCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
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

	var session *Session
	var sErr error
	sessionID := *sSession + *sKill
	session, sErr = server.getSession(sessionID)
	if sErr != nil {
		return fmt.Errorf("unknown session ID %d", sessionID)
	}

	if *sKill > 0 {
		if session.SSHInstance.IsEnabled() {
			if err := session.SSHInstance.Stop(); err != nil {
				return fmt.Errorf("error stopping SSH server: %w", err)
			}
			ui.PrintSuccess("SSH Endpoint gracefully stopped")
			return nil
		}
		ui.PrintInfo("No SSH Server on Session ID %d", *sKill)
		return nil
	}

	if *sSession > 0 {
		if session.SSHInstance.IsEnabled() {
			if port, pErr := session.SSHInstance.GetEndpointPort(); pErr == nil {
				return fmt.Errorf("ssh endpoint already running on port: %d", port)
			}
			return nil
		}
		ui.PrintInfo("Enabling SSH Endpoint in the background")

		// Receive Errors from Endpoint
		notifier := make(chan error, 1)
		defer close(notifier)
		// Give some time to check
		sshTicker := time.NewTicker(conf.EndpointTickerInterval)
		defer sshTicker.Stop()
		timeout := time.After(conf.Timeout)

		go session.sshEnable(*sPort, *sExpose, notifier)

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
			case <-sshTicker.C:
				port, sErr := session.SSHInstance.GetEndpointPort()
				if port == 0 || sErr != nil {
					fmt.Printf(".")
					continue
				}
				ui.PrintSuccess("SSH Endpoint running on port: %d", port)
				return nil
			case <-timeout:
				return fmt.Errorf("ssh endpoint reached timeout trying to start")
			}
		}
	}
	return nil
}
