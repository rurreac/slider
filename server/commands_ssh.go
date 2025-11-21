package server

import (
	"errors"
	"fmt"
	"io"
	"slider/pkg/conf"
	"time"

	"github.com/spf13/pflag"
)

// SSHCommand implements the 'ssh' command
type SSHCommand struct{}

func (c *SSHCommand) Name() string        { return sshCmd }
func (c *SSHCommand) Description() string { return sshDesc }
func (c *SSHCommand) Usage() string       { return sshUsage }

func (c *SSHCommand) Run(s *server, args []string, out io.Writer) error {
	sshFlags := pflag.NewFlagSet(sshCmd, pflag.ContinueOnError)
	sshFlags.SetOutput(out)

	sSession := sshFlags.IntP("session", "s", 0, "Session ID to establish SSH connection with")
	sPort := sshFlags.IntP("port", "p", 0, "Local port to forward SSH connection to")
	sKill := sshFlags.IntP("kill", "k", 0, "Kill SSH port forwarding to a Session ID")
	sExpose := sshFlags.BoolP("expose", "e", false, "Expose port to all interfaces")

	sshFlags.Usage = func() {
		fmt.Fprintf(out, "Usage: %s\n\n", sshUsage)
		fmt.Fprintf(out, "%s\n\n", sshDesc)
		sshFlags.PrintDefaults()
	}

	if pErr := sshFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return nil
	}

	// Validate one required
	if !sshFlags.Changed("session") && !sshFlags.Changed("kill") {
		s.console.PrintlnErrorStep("one of the flags --session or --kill must be set")
		return nil
	}

	// Validate mutual exclusion
	if sshFlags.Changed("session") && sshFlags.Changed("kill") {
		s.console.PrintlnErrorStep("flags --session and --kill cannot be used together")
		return nil
	}
	if sshFlags.Changed("kill") && sshFlags.Changed("port") {
		s.console.PrintlnErrorStep("flags --kill and --port cannot be used together")
		return nil
	}
	if sshFlags.Changed("kill") && sshFlags.Changed("expose") {
		s.console.PrintlnErrorStep("flags --kill and --expose cannot be used together")
		return nil
	}

	var session *Session
	var sessErr error
	sessionID := *sSession + *sKill
	session, sessErr = s.getSession(sessionID)
	if sessErr != nil {
		s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
		return nil
	}

	if *sKill > 0 {
		if session.SSHInstance.IsEnabled() {
			if err := session.SSHInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return nil
			}
			s.console.PrintlnOkStep("SSH Endpoint gracefully stopped")
			return nil
		}
		s.console.PrintlnDebugStep("No SSH Server on Session ID %d", *sKill)
		return nil
	}

	if *sSession > 0 {
		if session.SSHInstance.IsEnabled() {
			if port, pErr := session.SSHInstance.GetEndpointPort(); pErr == nil {
				s.console.PrintlnErrorStep("SSH Endpoint already running on port: %d", port)
			}
			return nil
		}
		s.console.PrintlnDebugStep("Enabling SSH Endpoint in the background")

		// Receive Errors from Endpoint
		notifier := make(chan error, 1)
		defer close(notifier)
		// Give some time to check
		sshTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)

		go session.sshEnable(*sPort, *sExpose, notifier)

		for {
			select {
			case nErr := <-notifier:
				if nErr != nil {
					s.console.PrintlnErrorStep("Endpoint error: %v", nErr)
					return nil
				}
			case <-sshTicker.C:
				if time.Now().Before(timeout) {
					port, sErr := session.SSHInstance.GetEndpointPort()
					if port == 0 || sErr != nil {
						fmt.Printf(".")
						continue
					}
					s.console.PrintlnOkStep("SSH Endpoint running on port: %d", port)
					return nil
				} else {
					s.console.PrintlnErrorStep("SSH Endpoint reached Timeout trying to start")
					return nil
				}
			}
		}
	}
	return nil
}
