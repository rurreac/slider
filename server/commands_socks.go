package server

import (
	"errors"
	"fmt"
	"io"
	"slider/pkg/conf"
	"time"

	"github.com/spf13/pflag"
)

// SocksCommand implements the 'socks' command
type SocksCommand struct{}

func (c *SocksCommand) Name() string        { return socksCmd }
func (c *SocksCommand) Description() string { return socksDesc }
func (c *SocksCommand) Usage() string       { return socksUsage }

func (c *SocksCommand) Run(s *server, args []string, out io.Writer) error {
	socksFlags := pflag.NewFlagSet(socksCmd, pflag.ContinueOnError)
	socksFlags.SetOutput(out)

	sSession := socksFlags.IntP("session", "s", 0, "Run a Socks5 server over an SSH Channel on a Session ID")
	sPort := socksFlags.IntP("port", "p", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill := socksFlags.IntP("kill", "k", 0, "Kill Socks5 Listener and Server on a Session ID")
	sExpose := socksFlags.BoolP("expose", "e", false, "Expose port to all interfaces")

	socksFlags.Usage = func() {
		fmt.Fprintf(out, "Usage: %s\n\n", socksUsage)
		fmt.Fprintf(out, "%s\n\n", socksDesc)
		socksFlags.PrintDefaults()
	}

	if pErr := socksFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return nil
	}

	// Validate one required
	if !socksFlags.Changed("session") && !socksFlags.Changed("kill") {
		s.console.PrintlnErrorStep("one of the flags --session or --kill must be set")
		return nil
	}

	// Validate mutual exclusion
	if socksFlags.Changed("session") && socksFlags.Changed("kill") {
		s.console.PrintlnErrorStep("flags --session and --kill cannot be used together")
		return nil
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("port") {
		s.console.PrintlnErrorStep("flags --kill and --port cannot be used together")
		return nil
	}
	if socksFlags.Changed("kill") && socksFlags.Changed("expose") {
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
		if session.SocksInstance.IsEnabled() {
			if err := session.SocksInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return nil
			}
			s.console.PrintlnOkStep("Socks Endpoint gracefully stopped")
			return nil
		}
		s.console.PrintlnDebugStep("No Socks Server on Session ID %d", *sKill)
		return nil
	}

	if *sSession > 0 {
		if session.SocksInstance.IsEnabled() {
			if port, pErr := session.SocksInstance.GetEndpointPort(); pErr == nil {
				s.console.PrintlnErrorStep("Socks Endpoint already running on port: %d", port)
			}
			return nil
		}
		s.console.PrintlnDebugStep("Enabling Socks Endpoint in the background")

		// Receive Errors from Endpoint
		notifier := make(chan error, 1)
		defer close(notifier)
		// Give some time to check
		socksTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)

		go session.socksEnable(*sPort, *sExpose, notifier)

		for {
			select {
			case nErr := <-notifier:
				if nErr != nil {
					s.console.PrintlnErrorStep("Endpoint error: %v", nErr)
					return nil
				}
			case <-socksTicker.C:
				if time.Now().Before(timeout) {
					port, sErr := session.SocksInstance.GetEndpointPort()
					if port == 0 || sErr != nil {
						fmt.Printf(".")
						continue
					}
					s.console.PrintlnOkStep("Socks Endpoint running on port: %d", port)
					return nil
				} else {
					s.console.PrintlnErrorStep("Socks Endpoint reached Timeout trying to start")
					return nil
				}
			}
		}
	}
	return nil
}
