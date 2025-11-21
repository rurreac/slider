package server

import (
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

// ShellCommand implements the 'shell' command
type ShellCommand struct{}

func (c *ShellCommand) Name() string        { return shellCmd }
func (c *ShellCommand) Description() string { return shellDesc }
func (c *ShellCommand) Usage() string       { return shellUsage }

func (c *ShellCommand) Run(s *server, args []string, out io.Writer) error {
	shellFlags := pflag.NewFlagSet(shellCmd, pflag.ContinueOnError)
	shellFlags.SetOutput(out)

	sSession := shellFlags.IntP("session", "s", 0, "Target Session ID for the shell")
	sPort := shellFlags.IntP("port", "p", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill := shellFlags.IntP("kill", "k", 0, "Kill Shell Listener and Server on a Session ID")
	sInteractive := shellFlags.BoolP("interactive", "i", false, "Interactive mode, enters shell directly. Always TLS")
	sTls := shellFlags.BoolP("tls", "t", false, "Enable TLS for the Shell")
	sExpose := shellFlags.BoolP("expose", "e", false, "Expose port to all interfaces")

	shellFlags.Usage = func() {
		fmt.Fprintf(out, "Usage: %s\n\n", shellUsage)
		fmt.Fprintf(out, "%s\n\n", shellDesc)
		shellFlags.PrintDefaults()
	}

	if pErr := shellFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return nil
	}

	// Validate one required
	if !shellFlags.Changed("session") && !shellFlags.Changed("kill") {
		s.console.PrintlnErrorStep("one of the flags --session or --kill must be set")
		return nil
	}

	// Validate mutual exclusion
	if shellFlags.Changed("session") && shellFlags.Changed("kill") {
		s.console.PrintlnErrorStep("flags --session and --kill cannot be used together")
		return nil
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("port") {
		s.console.PrintlnErrorStep("flags --kill and --port cannot be used together")
		return nil
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("interactive") {
		s.console.PrintlnErrorStep("flags --kill and --interactive cannot be used together")
		return nil
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("tls") {
		s.console.PrintlnErrorStep("flags --kill and --tls cannot be used together")
		return nil
	}
	if shellFlags.Changed("kill") && shellFlags.Changed("expose") {
		s.console.PrintlnErrorStep("flags --kill and --expose cannot be used together")
		return nil
	}
	if shellFlags.Changed("interactive") && shellFlags.Changed("expose") {
		s.console.PrintlnErrorStep("flags --interactive and --expose cannot be used together")
		return nil
	}
	if shellFlags.Changed("interactive") && shellFlags.Changed("tls") {
		s.console.PrintlnErrorStep("flags --interactive and --tls cannot be used together")
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
		if session.ShellInstance.IsEnabled() {
			if err := session.ShellInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return nil
			}
			s.console.PrintlnOkStep("Shell Endpoint gracefully stopped")
			return nil
		}
		s.console.PrintlnDebugStep("No Shell Server on Session ID %d", *sKill)
		return nil
	}

	if *sSession > 0 {
		if session.ShellInstance.IsEnabled() {
			if port, pErr := session.ShellInstance.GetEndpointPort(); pErr == nil {
				s.console.PrintlnErrorStep("Shell Endpoint already running on port: %d", port)
			}
			return nil
		}

		if *sInteractive {
			s.console.PrintlnDebugStep("Enabling Interactive Shell Endpoint in the background")
			*sTls = true
		} else {
			s.console.PrintlnDebugStep("Enabling Shell Endpoint in the background")
		}

		// Receive Errors from Endpoint
		notifier := make(chan error, 1)
		defer close(notifier)
		// Give some time to check
		shellTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)

		go session.shellEnable(*sPort, *sExpose, *sInteractive, *sTls, notifier)

		for {
			select {
			case nErr := <-notifier:
				if nErr != nil {
					s.console.PrintlnErrorStep("Endpoint error: %v", nErr)
					return nil
				}
			case <-shellTicker.C:
				if time.Now().Before(timeout) {
					port, sErr := session.ShellInstance.GetEndpointPort()
					if port == 0 || sErr != nil {
						fmt.Printf(".")
						continue
					}
					s.console.PrintlnOkStep("Shell Endpoint running on port: %d", port)
					if *sInteractive {
						s.console.PrintlnInfo("Connecting to Shell...")
						c.interactiveShell(s, port)
					}
					return nil
				} else {
					s.console.PrintlnErrorStep("Shell Endpoint reached Timeout trying to start")
					return nil
				}
			}
		}
	}
	return nil
}

func (c *ShellCommand) interactiveShell(s *server, port int) {
	// Wait for the server to start
	time.Sleep(1 * time.Second)

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		s.console.PrintlnErrorStep("Failed to connect to shell: %v", err)
		return
	}
	defer conn.Close()

	// Set console to raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		s.console.PrintlnErrorStep("Failed to set raw mode: %v", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	// Pipe stdin/stdout/stderr
	go func() {
		_, _ = io.Copy(conn, os.Stdin)
	}()
	_, _ = io.Copy(os.Stdout, conn)
}
