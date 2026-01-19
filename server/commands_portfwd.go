package server

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"slider/pkg/conf"
	"slider/pkg/instance"
	"slider/pkg/remote"

	"github.com/spf13/pflag"
)

const (
	// Console Port Forwarding Command
	portFwdCmd   = "portfwd"
	portFwdDesc  = "Creates a port forwarding tunnel"
	portFwdUsage = "Usage: portfwd [flags] <[a_addr]:a_port:[b_addr]:b_port>"
)

// PortFwdCommand implements the 'portfwd' command
type PortFwdCommand struct{}

func (c *PortFwdCommand) Name() string             { return portFwdCmd }
func (c *PortFwdCommand) Description() string      { return portFwdDesc }
func (c *PortFwdCommand) Usage() string            { return portFwdUsage }
func (c *PortFwdCommand) IsRemoteCompletion() bool { return false }
func (c *PortFwdCommand) Run(ctx *ExecutionContext, args []string) error {
	svr := ctx.getServer()
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
		return pErr
	}

	// Validate mutual exclusion
	if portFwdFlags.Changed("local") && portFwdFlags.Changed("reverse") {
		return fmt.Errorf("flags --local and --reverse cannot be used together")
	}

	// Validate flag requires args
	if portFwdFlags.Changed("local") {
		if portFwdFlags.NArg() != 1 || (!portFwdFlags.Changed("session")) {
			return fmt.Errorf("flag --local requires exactly 1 argument(s) and the session flag")
		}
	}
	if portFwdFlags.Changed("reverse") {
		if portFwdFlags.NArg() != 1 || (!portFwdFlags.Changed("session")) {
			return fmt.Errorf("flag --reverse requires exactly 1 argument(s) and the session flag")
		}
	}
	if portFwdFlags.Changed("remove") {
		if portFwdFlags.NArg() != 1 || (!portFwdFlags.Changed("session")) || (!portFwdFlags.Changed("reverse") && !portFwdFlags.Changed("local")) {
			return fmt.Errorf("flag --remove requires exactly 1 argument(s), the session flag and the reverse or local flag")
		}
	}
	if portFwdFlags.Changed("session") {
		if portFwdFlags.NArg() != 1 || (!portFwdFlags.Changed("reverse") && !portFwdFlags.Changed("local")) {
			return fmt.Errorf("flag --session requires exactly 1 argument(s) and the reverse or local flag")
		}
	}
	if !portFwdFlags.Changed("session") && portFwdFlags.NArg() != 0 {
		if !portFwdFlags.Changed("local") && !portFwdFlags.Changed("reverse") && !portFwdFlags.Changed("remove") {
			return fmt.Errorf("flag --session and at least one of the flags --local, --reverse or --remove must be specified")
		}
	}

	// Resolve Unified Sessions
	unifiedMap := svr.ResolveUnifiedSessions()
	var uSess UnifiedSession
	var isRemote bool

	if *pSession > 0 {
		if val, ok := unifiedMap[int64(*pSession)]; ok {
			if strings.HasPrefix(val.Role, "operator") {
				return fmt.Errorf("portfwd command not allowed against operator roles")
			}
			uSess = val
			isRemote = uSess.OwnerID != 0
		} else {
			return fmt.Errorf("unknown session ID %d", *pSession)
		}
	}

	if portFwdFlags.NArg() == 0 {
		// List of the Port Forwarding
		tw := new(tabwriter.Writer)
		tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)

		totalGlobalTcpIp := 0

		// Local Sessions Listing
		sessionList := slices.Collect(maps.Values(svr.sessionTrack.Sessions))
		for _, sItem := range sessionList {
			totalGlobalTcpIp += listSessionForwarding(tw, sItem.GetID(), sItem.GetSSHInstance())
		}

		// Remote Sessions Listing
		svr.remoteSessionsMutex.Lock()
		keys := slices.Collect(maps.Keys(svr.remoteSessions))
		svr.remoteSessionsMutex.Unlock()

		for _, key := range keys {
			svr.remoteSessionsMutex.Lock()
			state := svr.remoteSessions[key]
			svr.remoteSessionsMutex.Unlock()

			if state.SSHInstance != nil {
				totalGlobalTcpIp += listSessionForwarding(tw, state.SSHInstance.SessionID, state.SSHInstance)
			}
		}

		ui.PrintInfo("Active Port Forwards: %d\n", totalGlobalTcpIp)
		return nil
	}

	// Flags Processing
	var fwdInstance *instance.Config
	if !isRemote {
		// Local Strategy
		if *pSession <= 0 {
			return fmt.Errorf("invalid session ID")
		}
		bidirSession, err := svr.GetSession(int(uSess.ActualID))
		if err != nil {
			return fmt.Errorf("local session %d not found", uSess.ActualID)
		}

		fwdInstance = bidirSession.GetSSHInstance()
		if fwdInstance == nil {
			return fmt.Errorf("ssh instance not found for session %d", uSess.ActualID)
		}
	} else {
		// Remote Strategy
		key := fmt.Sprintf("portfwd:%d:%v", uSess.OwnerID, uSess.Path)
		svr.remoteSessionsMutex.Lock()
		if _, ok := svr.remoteSessions[key]; !ok {
			svr.remoteSessions[key] = &RemoteSessionState{}
		}
		state := svr.remoteSessions[key]
		svr.remoteSessionsMutex.Unlock()

		// Ensure SSHInstance exists (generic)
		if state.SSHInstance == nil {
			gatewaySession, err := svr.GetSession(int(uSess.OwnerID))
			if err != nil {
				return fmt.Errorf("gateway session %d not found", uSess.OwnerID)
			}

			target := append([]int64{}, uSess.Path...)
			target = append(target, uSess.ActualID)

			remoteConn := remote.NewProxy(gatewaySession, target)

			config := instance.New(&instance.Config{
				Logger:       svr.Logger,
				SessionID:    uSess.UnifiedID,
				EndpointType: instance.SshEndpoint,
			})
			config.SetSSHConn(remoteConn)

			svr.remoteSessionsMutex.Lock()
			state.SSHInstance = config
			svr.remoteSessionsMutex.Unlock()
		}

		fwdInstance = state.SSHInstance
		if fwdInstance == nil {
			return fmt.Errorf("ssh instance not found for session %d", uSess.UnifiedID)
		}
	}

	if *pLocal {
		return handleLocalForward(svr, ui, fwdInstance, portFwdFlags.Args()[0], *pRemove)
	}
	if *pReverse {
		return handleReverseForward(svr, ui, fwdInstance, portFwdFlags.Args()[0], *pRemove)
	}

	return nil
}

// Helper to list forwardings
func listSessionForwarding(tw *tabwriter.Writer, sessionID int64, sshInst *instance.Config) int {
	if sshInst == nil {
		return 0
	}
	count := 0

	reverseMappings := sshInst.GetRemoteMappings()
	count += len(reverseMappings)
	if len(reverseMappings) > 0 {
		_, _ = fmt.Fprintln(tw)
		_, _ = fmt.Fprintf(tw, "\tID\tForward Address\tForward Port\tAllowed Address\tRemote Port\n")
		_, _ = fmt.Fprintf(tw, "\t--\t---------------\t------------\t---------------\t-----------\n")
		for _, mapping := range reverseMappings {
			address := mapping.DstHost
			port := fmt.Sprintf("%d", int(mapping.DstPort))
			if mapping.IsSshConn {
				address = "(ssh client)"
				port = "(ssh client)"
			}
			_, _ = fmt.Fprintf(tw, "\t%d\t%s\t%s\t%s\t%d\n", sessionID, address, port, mapping.SrcHost, int(mapping.SrcPort))
		}
		_, _ = fmt.Fprintln(tw)
		_ = tw.Flush()
	}

	localMappings := sshInst.GetLocalMappings()
	count += len(localMappings)
	if len(localMappings) > 0 {
		_, _ = fmt.Fprintln(tw)
		_, _ = fmt.Fprintf(tw, "\tID\tLocal Address\tLocal Port\tForward Address\tForward Port\n")
		_, _ = fmt.Fprintf(tw, "\t--\t-------------\t----------\t---------------\t------------\n")
		for _, mapping := range localMappings {
			address := mapping.DstHost
			port := fmt.Sprintf("%d", int(mapping.DstPort))
			if mapping.IsSshConn {
				address = "(ssh client)"
				port = "(ssh client)"
			}
			_, _ = fmt.Fprintf(tw, "\t%d\t%s\t%d\t%s\t%s\n", sessionID, mapping.SrcHost, int(mapping.SrcPort), address, port)
		}
		_, _ = fmt.Fprintln(tw)
		_ = tw.Flush()
	}
	return count
}

func handleLocalForward(_ *server, ui UserInterface, sshInst *instance.Config, arg string, remove bool) error {
	if remove {
		port, pErr := parsePort(arg)
		if pErr != nil {
			return fmt.Errorf("error parsing port: %w", pErr)
		}
		mapping, mErr := sshInst.GetLocalPortMapping(port)
		if mErr != nil {
			return fmt.Errorf("error getting local port mapping: %w", mErr)
		}
		mapping.DoneChan <- true
		ui.PrintSuccess("Local Port forwarding (port %d) removed successfully", port)
		return nil
	}
	fwdItem := arg
	msg, pErr := parseForwarding(fwdItem, false)
	if pErr != nil {
		return fmt.Errorf("failed to parse port forwarding %s: %w", fwdItem, pErr)
	}
	ui.PrintInfo("Creating Port Forwarding %s:%d->%s:%d", msg.SrcHost, msg.SrcPort, msg.DstHost, msg.DstPort)

	notifier := make(chan error, 1)
	defer close(notifier)
	go sshInst.DirectTcpIpFromMsg(*msg.TcpIpChannelMsg, notifier)

	port := int(msg.SrcPort)
	ticker := time.NewTicker(conf.EndpointTickerInterval)
	defer ticker.Stop()
	timeout := time.After(conf.Timeout)

	for {
		select {
		case nErr := <-notifier:
			if nErr != nil {
				return fmt.Errorf("local port forward error: %w", nErr)
			}
		default:
		}
		select {
		case <-ticker.C:
			_, sErr := sshInst.GetLocalPortMapping(port)
			if sErr != nil {
				ui.FlatPrintf(".")
				continue
			}
			ui.PrintSuccess("Local Port Forward Endpoint running on port: %d", port)
			return nil
		case <-timeout:
			return fmt.Errorf("local port forward reached timeout trying to start")
		}
	}
}

func handleReverseForward(_ *server, ui UserInterface, sshInst *instance.Config, arg string, remove bool) error {
	if remove {
		port, pErr := parsePort(arg)
		if pErr != nil {
			return fmt.Errorf("error parsing port: %w", pErr)
		}
		sErr := sshInst.CancelMsgRemoteFwd(port)
		if sErr != nil {
			return fmt.Errorf("failed to remove: %w", sErr)
		}
		ui.PrintSuccess("Remote Port forwarding (port %d) removed successfully", port)
		return nil
	}
	fwdItem := arg
	msg, pErr := parseForwarding(fwdItem, true)
	if pErr != nil {
		return fmt.Errorf("failed to parse port forwarding %s: %w", fwdItem, pErr)
	}
	ui.PrintInfo("Creating Port Forwarding %s:%d -> %s:%d", msg.SrcHost, msg.SrcPort, msg.DstHost, msg.DstPort)

	notifier := make(chan error, 1)
	defer close(notifier)
	go sshInst.TcpIpForwardFromMsg(*msg, notifier)

	ticker := time.NewTicker(conf.EndpointTickerInterval)
	defer ticker.Stop()
	timeout := time.After(conf.Timeout)
	port := int(msg.SrcPort)
	for {
		select {
		case nErr := <-notifier:
			if nErr != nil {
				return fmt.Errorf("remote port forward error: %w", nErr)
			}
		default:
		}
		select {
		case <-ticker.C:
			_, sErr := sshInst.GetRemotePortMapping(port)
			if sErr != nil {
				ui.FlatPrintf(".")
				continue
			}
			ui.PrintSuccess("Remote Port Forward Endpoint running on port: %d", port)
			return nil
		case <-timeout:
			return fmt.Errorf("remote port forward reached timeout trying to start")
		}
	}
}
