package server

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"slider/pkg/conf"
	"text/tabwriter"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console Port Forwarding Command
	portFwdCmd   = "portfwd"
	portFwdDesc  = "Creates a port forwarding tunnel to / from a client"
	portFwdUsage = "Usage: portfwd [flags] <[local_addr]:local_port:[remote_addr]:remote_port>"
)

// PortFwdCommand implements the 'portfwd' command
type PortFwdCommand struct{}

func (c *PortFwdCommand) Name() string        { return portFwdCmd }
func (c *PortFwdCommand) Description() string { return portFwdDesc }
func (c *PortFwdCommand) Usage() string       { return portFwdUsage }

func (c *PortFwdCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
	ui := ctx.UI()

	portFwdFlags := pflag.NewFlagSet(portFwdCmd, pflag.ContinueOnError)
	portFwdFlags.SetOutput(ui.Writer())

	pSession := portFwdFlags.IntP("session", "s", 0, "Session ID to add or remove Port Forwarding")
	pLocal := portFwdFlags.BoolP("local", "L", false, "Local Port Forwarding <[local_addr]:local_port:[remote_addr]:remote_port>")
	pReverse := portFwdFlags.BoolP("reverse", "R", false, "Reverse format: <[allowed_remote_addr]:remote_port:[forward_addr]:forward_port>")
	pRemove := portFwdFlags.BoolP("remove", "r", false, "Remove Port Forwarding from port passed as argument (requires L or R)")

	portFwdFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", portFwdUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", portFwdDesc)
		portFwdFlags.PrintDefaults()
	}

	if pErr := portFwdFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		ui.PrintError("Flag error: %v", pErr)
		return nil
	}

	// Validate mutual exclusion
	if portFwdFlags.Changed("local") && portFwdFlags.Changed("reverse") {
		ui.PrintError("flags --local and --reverse cannot be used together")
		return nil
	}

	// Validate flag requires args
	if portFwdFlags.Changed("reverse") && portFwdFlags.NArg() != 1 {
		ui.PrintError("flag --reverse requires exactly 1 argument(s)")
		return nil
	}
	if portFwdFlags.Changed("local") && portFwdFlags.NArg() != 1 {
		ui.PrintError("flag --local requires exactly 1 argument(s)")
		return nil
	}
	if portFwdFlags.Changed("remove") && portFwdFlags.NArg() != 1 {
		ui.PrintError("flag --remove requires exactly 1 argument(s)")
		return nil
	}

	var session *Session
	if *pSession > 0 {
		var sErr error
		session, sErr = server.getSession(*pSession)
		if sErr != nil {
			ui.PrintError("Unknown Session ID %d", *pSession)
			return nil
		}
	}

	if portFwdFlags.NArg() == 0 {
		// List of the Port Forwarding
		tw := new(tabwriter.Writer)
		tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)

		totalGlobalTcpIp := 0
		sessionList := slices.Collect(maps.Values(server.sessionTrack.Sessions))

		for _, sItem := range sessionList {
			reverseMappings := sItem.SSHInstance.GetRemoteMappings()
			totalSessionTcpIpFwd := len(reverseMappings)
			totalGlobalTcpIp += totalSessionTcpIpFwd

			if totalSessionTcpIpFwd != 0 {
				_, _ = fmt.Fprintln(tw)
				_, _ = fmt.Fprintf(tw, "\tSession ID\tForward Address\tForward Port\tRemote Address\tRemote Port\n")
				_, _ = fmt.Fprintf(tw, "\t----------\t---------------\t----------\t--------------\t-----------\n")
				for _, mapping := range reverseMappings {
					var address string
					var port string
					if mapping.IsSshConn {
						address = "(ssh client)"
						port = "(ssh client)"
					} else {
						address = mapping.DstHost
						port = fmt.Sprintf("%d", int(mapping.DstPort))
					}
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t%s\t%s\t%d\n",
						sItem.sessionID,
						address, port,
						mapping.SrcHost, int(mapping.SrcPort),
					)
				}
				_, _ = fmt.Fprintln(tw)
				_ = tw.Flush()
			}

			localMappings := sItem.SSHInstance.GetLocalMappings()
			totalSessionDirectTcpIp := len(localMappings)
			totalGlobalTcpIp += totalSessionDirectTcpIp

			if totalSessionDirectTcpIp != 0 {
				_, _ = fmt.Fprintln(tw)
				_, _ = fmt.Fprintf(tw, "\tSession ID\tLocal Address\tLocal Port\tForward Address\tForward Port\n")
				_, _ = fmt.Fprintf(tw, "\t----------\t---------------\t----------\t--------------\t-----------\n")
				for _, mapping := range localMappings {
					var address string
					var port string
					if mapping.IsSshConn {
						address = "(ssh client)"
						port = "(ssh client)"
					} else {
						address = mapping.DstHost
						port = fmt.Sprintf("%d", int(mapping.DstPort))
					}
					_, _ = fmt.Fprintf(tw, "\t%d\t%s\t%d\t%s\t%s\n",
						sItem.sessionID,
						mapping.SrcHost, int(mapping.SrcPort),
						address, port,
					)
				}
				_, _ = fmt.Fprintln(tw)
				_ = tw.Flush()
			}
		}
		ui.PrintInfo("Active Port Forwards: %d\n", totalGlobalTcpIp)
		return nil
	}

	if *pLocal {
		if session == nil {
			ui.PrintError("Session ID not specified")
			return nil
		}
		if *pRemove {
			port, pErr := parsePort(portFwdFlags.Args()[0])
			if pErr != nil {
				ui.PrintError("Error: %v", pErr)
				return nil
			}
			mapping, mErr := session.SSHInstance.GetLocalPortMapping(port)
			if mErr != nil {
				ui.PrintError("Error: %v", mErr)
				return nil
			}
			mapping.DoneChan <- true
			ui.PrintSuccess("Local Port forwarding (port %d) removed successfully", port)
			return nil

		}
		fwdItem := portFwdFlags.Args()[0]
		msg, pErr := parseForwarding(fwdItem)
		if pErr != nil {
			ui.PrintError("Failed to parse Port Forwarding %s: %s", fwdItem, pErr)
			return nil
		}
		ui.PrintInfo("Creating Port Forwarding %s:%d->%s:%d", msg.SrcHost, msg.SrcPort, msg.DstHost, msg.DstPort)

		// Receive Errors from Instance
		notifier := make(chan error, 1)
		defer close(notifier)
		go session.SSHInstance.DirectTcpIpFromMsg(*msg.TcpIpChannelMsg, notifier)

		port := int(msg.SrcPort)
		ticker := time.NewTicker(conf.EndpointTickerInterval)
		defer ticker.Stop()
		timeout := time.After(conf.Timeout)

		for {
			// Priority check: always check notifier first
			select {
			case nErr := <-notifier:
				if nErr != nil {
					ui.PrintError("Local Port Forward error: %v", nErr)
					return nil
				}
			default:
				// Non-blocking, fall through
			}

			// Then check ticker and timeout
			select {
			case <-ticker.C:
				var sErr error
				_, sErr = session.SSHInstance.GetLocalPortMapping(port)
				if sErr != nil {
					fmt.Printf(".")
					continue
				}
				ui.PrintSuccess("Local Port Forward Endpoint running on port: %d", port)
				return nil
			case <-timeout:
				ui.PrintError("Local Port Forward reached Timeout trying to start")
				return nil
			}
		}
	}

	if *pReverse {
		if session == nil {
			ui.PrintError("Session ID not specified")
			return nil
		}

		if *pRemove {
			port, pErr := parsePort(portFwdFlags.Args()[0])
			if pErr != nil {
				ui.PrintError("Error: %v", pErr)
				return nil
			}
			sErr := session.SSHInstance.CancelMsgRemoteFwd(port)
			if sErr != nil {
				ui.PrintError("Failed to remove: %v", sErr)
				return nil
			}
			ui.PrintSuccess("Remote Port forwarding (port %d) removed successfully", port)
			return nil
		}

		// Create Reverse Port Forwarding
		fwdItem := portFwdFlags.Args()[0]
		msg, pErr := parseForwarding(fwdItem)
		if pErr != nil {
			ui.PrintError("Failed to parse Port Forwarding %s: %s", fwdItem, pErr)
			return nil
		}
		ui.PrintInfo("Creating Port Forwarding %s:%d->%s:%d", msg.SrcHost, msg.SrcPort, msg.DstHost, msg.DstPort)

		notifier := make(chan error, 1)
		defer close(notifier)
		go session.SSHInstance.TcpIpForwardFromMsg(*msg, notifier)

		ticker := time.NewTicker(conf.EndpointTickerInterval)
		defer ticker.Stop()
		timeout := time.After(conf.Timeout)
		port := int(msg.SrcPort)
		for {
			// Priority check: always check notifier first
			select {
			case nErr := <-notifier:
				if nErr != nil {
					ui.PrintError("Remote Port Forward error: %v", nErr)
					return nil
				}
			default:
				// Non-blocking, fall through
			}

			// Then check ticker and timeout
			select {
			case <-ticker.C:
				var sErr error
				_, sErr = session.SSHInstance.GetRemotePortMapping(port)
				if sErr != nil {
					fmt.Printf(".")
					continue
				}
				ui.PrintSuccess("Remote Port Forward Endpoint running on port: %d", port)
				return nil
			case <-timeout:
				ui.PrintError("Remote Port Forward reached Timeout trying to start")
				return nil
			}
		}
	}

	return nil
}
