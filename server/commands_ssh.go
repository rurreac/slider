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
		ui.PrintError("Flag error: %v", pErr)
		return nil
	}

	// Validate one required
	if !sshFlags.Changed("session") && !sshFlags.Changed("kill") {
		ui.PrintError("one of the flags --session or --kill must be set")
		return nil
	}

	// Validate mutual exclusion
	if sshFlags.Changed("session") && sshFlags.Changed("kill") {
		ui.PrintError("flags --session and --kill cannot be used together")
		return nil
	}
	if sshFlags.Changed("kill") && sshFlags.Changed("port") {
		ui.PrintError("flags --kill and --port cannot be used together")
		return nil
	}
	if sshFlags.Changed("kill") && sshFlags.Changed("expose") {
		ui.PrintError("flags --kill and --expose cannot be used together")
		return nil
	}

	var session *Session
	var sErr error
	sessionID := *sSession + *sKill
	session, sErr = server.getSession(sessionID)
	if sErr != nil {
		ui.PrintInfo("Unknown Session ID %d", sessionID)
		return nil
	}

	if *sKill > 0 {
		if session.SSHInstance.IsEnabled() {
			if err := session.SSHInstance.Stop(); err != nil {
				ui.PrintError("%v", err)
				return nil
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
				ui.PrintError("SSH Endpoint already running on port: %d", port)
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
					ui.PrintError("Endpoint error: %v", nErr)
					return nil
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
				ui.PrintError("SSH Endpoint reached Timeout trying to start")
				return nil
			}
		}
	}
	return nil
}
