package server

import (
	"errors"
	"fmt"
	"slider/pkg/conf"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console Socks Command
	socksCmd   = "socks"
	socksDesc  = "Runs a Socks5 server over an SSH Channel on a Session ID"
	socksUsage = "Usage: socks [flags]"
)

// SocksCommand implements the 'socks' command
type SocksCommand struct{}

func (c *SocksCommand) Name() string        { return socksCmd }
func (c *SocksCommand) Description() string { return socksDesc }
func (c *SocksCommand) Usage() string       { return socksUsage }

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

	var session *Session
	sessionID := *sSession + *sKill
	session, _ = server.getSession(*sSession)
	if session == nil {
		return fmt.Errorf("unknown session ID %d", sessionID)

	}

	if *sKill > 0 {
		if session.SocksInstance == nil {
			ui.PrintWarn("No SOCKS5 server running on session %d", sessionID)
			return nil
		}
		if err := session.SocksInstance.Stop(); err != nil { // Added error check for Stop()
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

		// Receive Errors from Endpoint
		notifier := make(chan error, 1)
		defer close(notifier)
		// Give some time to check
		socksTicker := time.NewTicker(conf.EndpointTickerInterval)
		defer socksTicker.Stop()
		timeout := time.After(conf.Timeout)

		go session.socksEnable(*sPort, *sExpose, notifier)

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
			case <-socksTicker.C:
				if session.SocksInstance != nil {
					port, portErr := session.SocksInstance.GetEndpointPort()
					if port == 0 || portErr != nil {
						fmt.Printf(".")
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
	return nil
}
