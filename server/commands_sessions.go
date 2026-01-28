package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"slider/pkg/interpreter"
	"slider/pkg/remote"
	"slider/pkg/session"

	"github.com/pkg/sftp"
	"github.com/spf13/pflag"
)

const (
	// Console Sessions Command
	sessionsCmd   = "sessions"
	sessionsDesc  = "Interacts with Client Sessions"
	sessionsUsage = "Usage: sessions [flags]"
)

// SessionsCommand implements the 'sessions' command
type SessionsCommand struct{}

// UnifiedSession represents a normalized session (local or remote)
type UnifiedSession struct {
	// Identifiers
	UnifiedID int64 // Unique ID for the session
	ActualID  int64 // Session ID as stored on the system that owns the session
	OwnerID   int64 // Parent unified ID for display (0 for direct local connections)
	GatewayID int64 // Local gateway session ID for routing (0 for local sessions)
	Role      string
	// System properties
	PtyOn      bool
	User       string
	Host       string
	System     string
	HomeDir    string
	WorkingDir string // Current SFTP working directory (if active)
	SliderDir  string // Binary path
	LaunchDir  string // Launch path
	// Connection type
	IsConnector    bool
	IsGateway      bool
	ConnectionAddr string
	Path           []int64
}

// pathKey is used to uniquely identify a remote session for parent resolution
type pathKey struct {
	gatewayID int64
	pathStr   string // String representation of path
	actualID  int64
}

// remoteSessionEntry holds a remote session with its gateway context
type remoteSessionEntry struct {
	rs             session.RemoteSession
	gatewayID      int64 // Local gateway session ID
	gatewayUnified int64 // Unified ID of the gateway
}

// ResolveUnifiedSessions aggregates local and remote sessions into a single list with Unified IDs
func (s *server) ResolveUnifiedSessions() map[int64]UnifiedSession {
	unifiedMap := make(map[int64]UnifiedSession)

	// Collect and process local sessions
	localSessions := s.GetAllSessions()
	maxID := s.collectLocalSessions(unifiedMap, localSessions)

	// Collect remote sessions from all gateways
	remoteEntries := s.collectRemoteSessions(localSessions)

	// Build lookup table for parent resolution
	remoteUnifiedLookup := s.buildRemoteLookup(remoteEntries, &maxID)

	// Create unified sessions for remote entries
	s.processRemoteSessions(unifiedMap, remoteEntries, remoteUnifiedLookup)

	return unifiedMap
}

// collectLocalSessions processes local sessions and returns the max ID used
func (s *server) collectLocalSessions(unifiedMap map[int64]UnifiedSession, sessions []*session.BidirectionalSession) int64 {
	maxID := int64(0)

	for _, sess := range sessions {
		uSess := s.createUnifiedFromLocal(sess)
		unifiedMap[uSess.UnifiedID] = uSess

		if sess.GetID() > maxID {
			maxID = sess.GetID()
		}
	}

	return maxID
}

// createUnifiedFromLocal creates a UnifiedSession from a local BidirectionalSession
func (s *server) createUnifiedFromLocal(sess *session.BidirectionalSession) UnifiedSession {
	uSess := UnifiedSession{
		UnifiedID: sess.GetID(),
		ActualID:  sess.GetID(),
		OwnerID:   sess.GetParentSessionID(), // 0 for direct, parent ID for beacon-tunneled
		User:      "unknown",
		Host:      "unknown",
		System:    "unknown",
	}

	peerInfo := sess.GetPeerInfo()

	if sess.GetRouter() != nil || (sess.GetSSHClient() != nil && !sess.GetIsListener()) {
		uSess.User = "server"
		if addr := sess.GetRemoteAddr(); addr != nil {
			uSess.Host = addr.String()
		}
		uSess.System = "unknown/unknown"
		uSess.HomeDir = "/"
		if peerInfo.User != "" {
			uSess.User = peerInfo.User
			uSess.Host = peerInfo.Hostname
			uSess.System = fmt.Sprintf("%s/%s", peerInfo.Arch, peerInfo.System)
			uSess.HomeDir = peerInfo.HomeDir
			uSess.SliderDir = peerInfo.SliderDir
			uSess.LaunchDir = peerInfo.LaunchDir
			uSess.PtyOn = peerInfo.PtyOn
		}
	} else if peerInfo.User != "" {
		uSess.User = peerInfo.User
		uSess.Host = peerInfo.Hostname
		uSess.System = fmt.Sprintf("%s/%s", peerInfo.Arch, peerInfo.System)
		uSess.HomeDir = peerInfo.HomeDir
		uSess.SliderDir = peerInfo.SliderDir
		uSess.LaunchDir = peerInfo.LaunchDir
		uSess.PtyOn = peerInfo.PtyOn
	}

	uSess.Role = sess.GetPeerRole().String()
	uSess.WorkingDir = sess.GetSftpWorkingDir()
	uSess.IsGateway = sess.GetIsGateway()

	return uSess
}

// collectRemoteSessions fetches remote sessions from all gateway sessions
func (s *server) collectRemoteSessions(localSessions []*session.BidirectionalSession) []remoteSessionEntry {
	var entries []remoteSessionEntry

	currentIdentity := fmt.Sprintf("%s:%d", s.fingerprint, s.port)
	visited := []string{currentIdentity}

	for _, sess := range localSessions {
		// Only query sessions that are actual gateways (have SSH client capability)
		if sess.GetIsGateway() && sess.GetSSHClient() != nil {
			remoteSessions, err := sess.GetRemoteSessions(visited)
			if err == nil {
				for _, rs := range remoteSessions {
					entries = append(entries, remoteSessionEntry{
						rs:             rs,
						gatewayID:      sess.GetID(),
						gatewayUnified: sess.GetID(), // For local sessions, UnifiedID == ActualID
					})
				}
			}
		}
	}

	return entries
}

// buildRemoteLookup creates a lookup table mapping (gateway, path, actualID) -> unifiedID
func (s *server) buildRemoteLookup(entries []remoteSessionEntry, maxID *int64) map[pathKey]int64 {
	lookup := make(map[pathKey]int64)

	for _, entry := range entries {
		*maxID++
		key := pathKey{
			gatewayID: entry.gatewayID,
			pathStr:   fmt.Sprintf("%v", entry.rs.Path),
			actualID:  entry.rs.ID,
		}
		lookup[key] = *maxID
	}

	return lookup
}

// processRemoteSessions creates UnifiedSessions for all remote entries
func (s *server) processRemoteSessions(unifiedMap map[int64]UnifiedSession, entries []remoteSessionEntry, lookup map[pathKey]int64) {
	for _, entry := range entries {
		uSess := s.createUnifiedFromRemote(entry, lookup)
		unifiedMap[uSess.UnifiedID] = uSess
	}
}

// createUnifiedFromRemote creates a UnifiedSession from a remote session entry
func (s *server) createUnifiedFromRemote(entry remoteSessionEntry, lookup map[pathKey]int64) UnifiedSession {
	rs := entry.rs

	system := fmt.Sprintf("%s/%s", rs.Arch, rs.System)
	if rs.System == "" || rs.Arch == "" {
		system = "REMOTE"
	}

	ownerID := s.resolveRemoteOwner(entry, lookup)

	// Get the unified ID for this session
	key := pathKey{
		gatewayID: entry.gatewayID,
		pathStr:   fmt.Sprintf("%v", rs.Path),
		actualID:  rs.ID,
	}
	unifiedID := lookup[key]

	return UnifiedSession{
		UnifiedID:      unifiedID,
		ActualID:       rs.ID,
		OwnerID:        ownerID,
		GatewayID:      entry.gatewayID, // Local gateway for routing
		User:           rs.User,
		Host:           rs.Hostname,
		System:         system,
		Role:           rs.Role,
		HomeDir:        rs.HomeDir,
		WorkingDir:     rs.WorkingDir,
		SliderDir:      rs.SliderDir,
		LaunchDir:      rs.LaunchDir,
		IsConnector:    rs.IsConnector,
		IsGateway:      rs.IsGateway,
		ConnectionAddr: rs.ConnectionAddr,
		Path:           rs.Path,
		PtyOn:          rs.PtyOn,
	}
}

// resolveRemoteOwner determines the parent unified ID for a remote session
func (s *server) resolveRemoteOwner(entry remoteSessionEntry, lookup map[pathKey]int64) int64 {
	rs := entry.rs

	// Direct child of local gateway (no path)
	if len(rs.Path) == 0 {
		return entry.gatewayUnified
	}

	// Has explicit parent session ID - look up its unified ID
	if rs.ParentSessionID != 0 {
		parentKey := pathKey{
			gatewayID: entry.gatewayID,
			pathStr:   fmt.Sprintf("%v", rs.Path),
			actualID:  rs.ParentSessionID,
		}
		if parentUnified, found := lookup[parentKey]; found {
			return parentUnified
		}
		// Fallback to path-based resolution
	}

	// Parent is the session at the end of the path
	// Look up: path = rs.Path[:-1], actualID = rs.Path[last]
	parentPath := rs.Path[:len(rs.Path)-1]
	parentActualID := rs.Path[len(rs.Path)-1]
	parentKey := pathKey{
		gatewayID: entry.gatewayID,
		pathStr:   fmt.Sprintf("%v", parentPath),
		actualID:  parentActualID,
	}
	if parentUnified, found := lookup[parentKey]; found {
		return parentUnified
	}

	// Final fallback: gateway is the owner
	return entry.gatewayUnified
}

func (c *SessionsCommand) Name() string             { return sessionsCmd }
func (c *SessionsCommand) Description() string      { return sessionsDesc }
func (c *SessionsCommand) Usage() string            { return sessionsUsage }
func (c *SessionsCommand) IsRemoteCompletion() bool { return false }
func (c *SessionsCommand) Run(ctx *ExecutionContext, args []string) error {
	svr := ctx.getServer()
	ui := ctx.UI()

	var list bool
	sessionsFlags := pflag.NewFlagSet(sessionsCmd, pflag.ContinueOnError)
	sessionsFlags.SetOutput(ui.Writer())

	sInteract := sessionsFlags.IntP("interactive", "i", 0, "Start Interactive Slider Shell on a Session ID")
	sDisconnect := sessionsFlags.IntP("disconnect", "d", 0, "Disconnect Session ID")
	sKill := sessionsFlags.IntP("kill", "k", 0, "Kill Session ID")

	sessionsFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", sessionsUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", sessionsDesc)
		sessionsFlags.PrintDefaults()
	}

	if pErr := sessionsFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
	}

	if len(sessionsFlags.Args()) > 0 {
		return fmt.Errorf("too many arguments")
	}

	// Validate mutual exclusion
	changedCount := 0
	if sessionsFlags.Changed("interactive") {
		changedCount++
	}
	if sessionsFlags.Changed("disconnect") {
		changedCount++
	}
	if sessionsFlags.Changed("kill") {
		changedCount++
	}
	if changedCount > 1 {
		return fmt.Errorf("flags --interactive, --disconnect and --kill cannot be used together")
	}

	if len(args) == 0 {
		list = true
	}

	if list {
		// Use resolveSessions to get all sessions (local + remote) with unified IDs
		unifiedMap := svr.ResolveUnifiedSessions()

		if len(unifiedMap) > 0 {
			var keys []int
			for k := range unifiedMap {
				keys = append(keys, int(k))
			}
			sort.Ints(keys)

			// Build set of sessions that have children (beacons/relays)
			// A session is a beacon if other sessions have it as their OwnerID
			hasChildren := make(map[int64]bool)
			for _, uSess := range unifiedMap {
				if uSess.OwnerID != 0 {
					hasChildren[uSess.OwnerID] = true
				}
			}

			tw := new(tabwriter.Writer)
			tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
			// Added Role column
			_, _ = fmt.Fprintf(tw, "\n\tID\tOwner\tSystem\tRole\tUser\tHost\tIO\tConnection\tSSH/SFTP\tShell/TLS\tCertID\t")
			_, _ = fmt.Fprintf(tw, "\n\t--\t-----\t------\t----\t----\t----\t--\t----------\t--------\t---------\t------\t\n")

			for _, i := range keys {
				uSess := unifiedMap[int64(i)]

				// Defaults for Remote
				sshPort := "--"
				shellPort := "--"
				shellTLS := "--"
				certID := "--"
				inOut := "--"
				connection := "--"

				// If Local (GatewayID == 0), fetch detailed info from actual session
				if uSess.GatewayID == 0 {
					if sess, ok := svr.sessionTrack.Sessions[uSess.ActualID]; ok {
						if sess.GetSSHInstance().IsEnabled() {
							if port, pErr := sess.GetSSHInstance().GetEndpointPort(); pErr == nil {
								sshPort = fmt.Sprintf("%d", port)
							}
						}
						if sess.GetShellInstance().IsEnabled() {
							if port, pErr := sess.GetShellInstance().GetEndpointPort(); pErr == nil {
								shellPort = fmt.Sprintf("%d", port)
							}
							shellTLS = "off"
							if sess.GetShellInstance().IsTLSOn() {
								shellTLS = "on"
							}
						}
						certIDVal, _ := sess.GetCertInfo()
						if svr.authOn && certIDVal != 0 {
							certID = fmt.Sprintf("%d", certIDVal)
						}
						inOut = "<-"
						if sess.GetRole().IsConnector() {
							inOut = "->"
						}
						if addr := sess.GetRemoteAddr(); addr != nil {
							connection = addr.String()
						}
					}
				} else {
					// Remote Session Logic
					// Set IO and Connection from remote session info
					inOut = "<-"
					if uSess.IsConnector {
						inOut = "->"
					}
					connection = uSess.ConnectionAddr

					// Check for SSH using GatewayID for state key
					sshKey := fmt.Sprintf("ssh:%d:%v", uSess.GatewayID, uSess.Path)
					svr.remoteSessionsMutex.Lock()
					if state, ok := svr.remoteSessions[sshKey]; ok {
						if state.SSHInstance != nil && state.SSHInstance.IsEnabled() {
							if port, pErr := state.SSHInstance.GetEndpointPort(); pErr == nil {
								sshPort = fmt.Sprintf("%d", port)
							}
						}
					}
					svr.remoteSessionsMutex.Unlock()

					// Check for Shell using GatewayID for state key
					shellKey := fmt.Sprintf("shell:%d:%v", uSess.GatewayID, uSess.Path)
					svr.remoteSessionsMutex.Lock()
					if state, ok := svr.remoteSessions[shellKey]; ok {
						if state.ShellInstance != nil && state.ShellInstance.IsEnabled() {
							if port, pErr := state.ShellInstance.GetEndpointPort(); pErr == nil {
								shellPort = fmt.Sprintf("%d", port)
								// Check if TLS is enabled
								if state.ShellInstance.IsTLSOn() {
									shellTLS = "on"
								}
							}
						}
					}
					svr.remoteSessionsMutex.Unlock()
				}

				ownerStr := "LOCAL"
				if uSess.OwnerID != 0 {
					ownerStr = fmt.Sprintf("%d", uSess.OwnerID)
				}

				// Truncate host if needed
				hostname := uSess.Host
				if len(hostname) > 15 {
					hostname = hostname[:15] + "..."
				}

				// Build role display
				roleDisplay := uSess.Role
				if uSess.IsGateway {
					// Gateway
					roleDisplay += "·G"
					// Beacon
				} else if hasChildren[uSess.UnifiedID] {
					roleDisplay += "·B"
				}

				_, _ = fmt.Fprintf(tw, "\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
					uSess.UnifiedID,
					ownerStr,
					uSess.System,
					roleDisplay,
					uSess.User,
					hostname,
					inOut,
					connection,
					sshPort,
					fmt.Sprintf("%s/%s", shellPort, shellTLS),
					certID,
				)
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		ui.PrintInfo("Active sessions: %d\n", svr.sessionTrack.SessionActive)
		return nil
	}

	if *sDisconnect != 0 {
		sess, sessErr := svr.GetSession(*sDisconnect)
		if sessErr != nil {
			return fmt.Errorf("unknown session ID %d", *sDisconnect)
		}
		if cErr := sess.GetWebSocketConn().Close(); cErr != nil {
			return fmt.Errorf("failed to close connection to session ID %d: %w", sess.GetID(), cErr)
		}
		ui.PrintSuccess("Closed connection to Session ID %d", sess.GetID())
		return nil
	}

	if *sKill != 0 {
		sess, sessErr := svr.GetSession(*sKill)
		if sessErr != nil {
			return fmt.Errorf("unknown session ID %d", *sKill)
		}
		var err error
		if _, _, err = sess.SendRequest(
			"shutdown",
			true,
			nil,
		); err != nil {
			return fmt.Errorf("client did not answer properly to the request: %w", err)
		}
		ui.PrintSuccess("SessionID %d terminated gracefully", *sKill)

		return nil
	}

	if *sInteract != 0 {
		unifiedMap := svr.ResolveUnifiedSessions()
		uSess, ok := unifiedMap[int64(*sInteract)]
		if !ok {
			return fmt.Errorf("session %d not found", *sInteract)
		}

		if strings.HasPrefix(uSess.Role, "operator") {
			return fmt.Errorf("interactive session not allowed against operator roles")
		}

		// GatewayID == 0 means local session
		// GatewayID != 0 means remote session accessed via that gateway
		if uSess.GatewayID == 0 {
			// LOCAL SESSION
			sess, sessErr := svr.GetSession(int(uSess.ActualID))
			if sessErr != nil {
				return fmt.Errorf("session %d not found", uSess.ActualID)
			}

			sftpCli, sErr := sess.NewSftpClient()
			if sErr != nil {
				return fmt.Errorf("failed to create SFTP client: %w", sErr)
			}
			defer func() { _ = sftpCli.Close() }()

			console, ok := ui.(*Console)
			if !ok {
				return fmt.Errorf("UI is not a Console")
			}

			// Use LatestDir from the unified session for directory persistence
			opt := SftpConsoleOptions{
				Session:    sess,
				SftpClient: sftpCli,
				LatestDir:  uSess.WorkingDir,
				RemoteInfo: sess.GetPeerInfo(),
			}
			svr.newSftpConsoleWithInterpreter(console, opt)
			console.setConsoleAutoComplete(svr.commandRegistry, svr.serverInterpreter)
			return nil
		}
		// REMOTE SESSION
		// Get Gateway Session using GatewayID (the local session through which we reach the remote)
		gatewaySession, sessErr := svr.GetSession(int(uSess.GatewayID))
		if sessErr != nil {
			return fmt.Errorf("gateway session %d not found", uSess.GatewayID)
		}

		if gatewaySession.GetSSHClient() == nil {
			return fmt.Errorf("gateway session %d is not promiscuous", uSess.GatewayID)
		}

		// Construct Target Path for slider-connect.
		// Format: [ID, ID, ID...]
		target := append([]int64{}, uSess.Path...)
		// If path is empty (direct child), target is just [ActualID]
		target = append(target, uSess.ActualID)

		// Connect via slider-connect channel
		connReq := remote.ConnectRequest{
			Target:      target,
			ChannelType: "sftp",
		}
		payload, _ := json.Marshal(connReq)

		sftpChan, reqs, err := gatewaySession.GetSSHClient().OpenChannel("slider-connect", payload)
		if err != nil {
			return fmt.Errorf("failed to open remote channel to %d: %v", target, err)
		}

		// Parse the target system info from UnifiedSession and create a separate interpreter
		// This interpreter is NOT shared and won't interfere with other remote sessions

		systemParts := strings.Split(uSess.System, "/")
		remoteSystem := "unknown"
		remoteArch := "unknown"
		if len(systemParts) >= 2 {
			remoteArch = systemParts[0]
			systemStr := systemParts[1]
			if idx := strings.Index(systemStr, " "); idx >= 0 {
				systemStr = systemStr[:idx]
			}
			remoteSystem = strings.ToLower(systemStr)
		}

		// Get HomeDir from UnifiedSession - convert to SFTP format if needed
		homeDir := uSess.HomeDir
		if remoteSystem == "windows" {
			if strings.Contains(homeDir, "\\") {
				homeDir = "/" + strings.ReplaceAll(homeDir, "\\", "/")
			} else if !strings.HasPrefix(homeDir, "/") && homeDir != "/" {
				homeDir = "/" + homeDir
			}
		}

		remoteInfo := interpreter.BaseInfo{
			User:      uSess.User,
			Hostname:  uSess.Host,
			HomeDir:   homeDir,
			System:    remoteSystem,
			Arch:      remoteArch,
			SliderDir: uSess.SliderDir,
			LaunchDir: uSess.LaunchDir,
		}

		// Handle channel requests in background
		// When client-info arrives, update our separate interpreter
		go func() {
			for req := range reqs {
				switch req.Type {
				case "keep-alive":
					_ = gatewaySession.ReplyConnRequest(req, true, []byte("pong"))
				case "client-info":
					ci := &interpreter.Info{}
					if jErr := json.Unmarshal(req.Payload, ci); jErr == nil {
						// Update the remote interpreter (NOT the gateway session's interpreter)
						// Convert HomeDir to SFTP format for Windows systems if needed
						homeDir := ci.HomeDir
						if strings.ToLower(ci.System) == "windows" {
							// Only convert if it's in native Windows format (contains backslashes)
							if strings.Contains(homeDir, "\\") {
								homeDir = "/" + strings.ReplaceAll(homeDir, "\\", "/")
							} else if !strings.HasPrefix(homeDir, "/") && homeDir != "/" {
								// Handle case where Windows path uses forward slashes but isn't in SFTP format
								homeDir = "/" + homeDir
							}
						}
						// Copy the updated values to our remote interpreter
						remoteInfo.User = ci.User
						remoteInfo.Hostname = ci.Hostname
						remoteInfo.HomeDir = homeDir
						remoteInfo.System = strings.ToLower(ci.System)
						remoteInfo.Arch = ci.Arch
						remoteInfo.SliderDir = ci.SliderDir
						remoteInfo.LaunchDir = ci.LaunchDir
					}
					_ = gatewaySession.ReplyConnRequest(req, true, nil)
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()

		// Wrap in the SFTP client
		sftpCli, err := sftp.NewClientPipe(sftpChan, sftpChan)
		if err != nil {
			_ = sftpChan.Close()
			return fmt.Errorf("failed to create SFTP client: %v", err)
		}
		defer func() {
			_ = sftpCli.Close()
		}()

		console, ok := ui.(*Console)
		if !ok {
			return fmt.Errorf("UI is not a Console")
		}

		// Use the unified session ID for display and pass the separate interpreter
		svr.newSftpConsoleWithInterpreter(console, SftpConsoleOptions{
			Session:         gatewaySession,
			SftpClient:      sftpCli,
			RemoteInfo:      remoteInfo,
			targetSessionID: uSess.UnifiedID,
			LatestDir:       uSess.WorkingDir,
		})
		console.setConsoleAutoComplete(svr.commandRegistry, svr.serverInterpreter)
	}

	return nil
}
