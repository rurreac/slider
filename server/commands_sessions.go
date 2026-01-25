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
	UnifiedID      int64
	ActualID       int64
	OwnerID        int64  // 0 for local, valid Session ID for remote gateway
	Type           string // "LOCAL", "PROMISCUOUS/SERVER", "REMOTE"
	User           string
	Host           string
	System         string
	Role           string
	HomeDir        string
	WorkingDir     string // Current SFTP working directory (if active)
	SliderDir      string // Binary path
	LaunchDir      string // Launch path
	Extra          string // For port info etc
	IsConnector    bool
	IsGateway      bool
	ConnectionAddr string
	Path           []int64
	PtyOn          bool
}

// ResolveUnifiedSessions aggregates local and remote sessions into a single list with Unified IDs
func (s *server) ResolveUnifiedSessions() map[int64]UnifiedSession {
	unifiedMap := make(map[int64]UnifiedSession)

	maxID := int64(0)

	// 1. Collect Local Sessions
	localSessions := s.GetAllSessions()

	for _, sess := range localSessions {
		uSess := UnifiedSession{
			UnifiedID: sess.GetID(),
			ActualID:  sess.GetID(),
			OwnerID:   0,
			User:      "unknown",
			Host:      "unknown",
			System:    "unknown",
		}

		if sess.GetID() > maxID {
			maxID = sess.GetID()
		}

		if sess.GetRouter() != nil || (sess.GetSSHClient() != nil && !sess.GetIsListener()) {
			uSess.Type = "PROMISCUOUS"
			if sess.GetSSHClient() != nil {
				uSess.Type = "PROMISCUOUS/SERVER"
			} else {
				uSess.Type = "PROMISCUOUS/CLIENT"
			}
			uSess.User = "server"
			uSess.Host = sess.GetWebSocketConn().RemoteAddr().String()
			uSess.System = "unknown/unknown"
			uSess.HomeDir = "/"
			if sess.GetPeerInfo().User != "" {
				uSess.User = sess.GetPeerInfo().User
				uSess.Host = sess.GetPeerInfo().Hostname
				uSess.System = fmt.Sprintf("%s/%s", sess.GetPeerInfo().Arch, sess.GetPeerInfo().System)
				uSess.HomeDir = sess.GetPeerInfo().HomeDir
				uSess.SliderDir = sess.GetPeerInfo().SliderDir
				uSess.LaunchDir = sess.GetPeerInfo().LaunchDir
				uSess.PtyOn = sess.GetPeerInfo().PtyOn
			}
		} else if sess.GetPeerInfo().User != "" {
			uSess.User = sess.GetPeerInfo().User
			uSess.Host = sess.GetPeerInfo().Hostname
			uSess.System = fmt.Sprintf("%s/%s", sess.GetPeerInfo().Arch, sess.GetPeerInfo().System)
			uSess.HomeDir = sess.GetPeerInfo().HomeDir
			uSess.SliderDir = sess.GetPeerInfo().SliderDir
			uSess.LaunchDir = sess.GetPeerInfo().LaunchDir
			uSess.Type = "LOCAL"
			uSess.PtyOn = sess.GetPeerInfo().PtyOn
		}

		uSess.Role = sess.GetPeerRole().String()

		// Get the current SFTP working directory if available
		uSess.WorkingDir = sess.GetSftpWorkingDir()
		uSess.IsGateway = sess.GetIsGateway()
		unifiedMap[uSess.UnifiedID] = uSess
	}

	// 2. Collect Remote Sessions
	// Iterate only over Gateways/Servers
	for _, sess := range localSessions {
		if sess.GetRouter() != nil || sess.GetSSHClient() != nil {
			// Fetch remotes
			currentIdentity := fmt.Sprintf("%s:%d", s.fingerprint, s.port)
			visited := []string{currentIdentity}
			remoteSessions, err := sess.GetRemoteSessions(visited)
			if err == nil {
				for _, rs := range remoteSessions {
					// Assign new Unified ID
					maxID++
					system := fmt.Sprintf("%s/%s", rs.Arch, rs.System)
					if rs.System == "unknown" || rs.Arch == "unknown" {
						system = "REMOTE"
					}
					uSess := UnifiedSession{
						UnifiedID:      maxID,
						ActualID:       rs.ID,
						OwnerID:        sess.GetID(), // This local session is the gateway
						Type:           "REMOTE",
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
						Path:           rs.Path, // Path from the remote perspective (relative to Owner)
						PtyOn:          rs.PtyOn,
					}
					unifiedMap[uSess.UnifiedID] = uSess
				}
			}
		}
	}

	return unifiedMap
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

	if len(args) > 0 {
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

				// If Local, fetch detailed info from actual session
				if uSess.OwnerID == 0 {
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
						connection = sess.GetWebSocketConn().RemoteAddr().String()
					}
				} else {
					// Remote Session Logic
					// Set IO and Connection from remote session info
					inOut = "<-"
					if uSess.IsConnector {
						inOut = "->"
					}
					connection = uSess.ConnectionAddr

					// Check for SSH
					sshKey := fmt.Sprintf("ssh:%d:%v", uSess.OwnerID, uSess.Path)
					svr.remoteSessionsMutex.Lock()
					if state, ok := svr.remoteSessions[sshKey]; ok {
						if state.SSHInstance != nil && state.SSHInstance.IsEnabled() {
							if port, pErr := state.SSHInstance.GetEndpointPort(); pErr == nil {
								sshPort = fmt.Sprintf("%d", port)
							}
						}
					}
					svr.remoteSessionsMutex.Unlock()

					// Check for Shell
					shellKey := fmt.Sprintf("shell:%d:%v", uSess.OwnerID, uSess.Path)
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

				_, _ = fmt.Fprintf(tw, "\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
					uSess.UnifiedID,
					ownerStr,
					uSess.System,
					uSess.Role,
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

		// ROUTE BASED ON LOCAL vs REMOTE
		if uSess.OwnerID == 0 {
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
			// Use the working directory from the unified session
			svr.newSftpConsoleWithInterpreter(console, SftpConsoleOptions{
				Session:    sess,
				SftpClient: sftpCli,
				LatestDir:  uSess.WorkingDir,
			})
			console.setConsoleAutoComplete(svr.commandRegistry, svr.serverInterpreter)
			return nil
		}

		// REMOTE SESSION
		// 1. Get Gateway Session
		gatewaySession, sessErr := svr.GetSession(int(uSess.OwnerID))
		if sessErr != nil {
			return fmt.Errorf("gateway session %d not found", uSess.OwnerID)
		}

		if gatewaySession.GetSSHClient() == nil {
			return fmt.Errorf("gateway session %d is not promiscuous", uSess.OwnerID)
		}

		// 2. Construct Target Path for slider-connect
		// Format: [ID, ID, ID...]
		// If path is empty (direct child), target is just [ActualID]
		target := append([]int64{}, uSess.Path...)
		target = append(target, uSess.ActualID)

		// 3. Connect via slider-connect channel
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

		// Parse "arch/system" or "arch/system (P)" format
		systemParts := strings.Split(uSess.System, "/")
		remoteSystem := "unknown"
		remoteArch := "unknown"
		if len(systemParts) >= 2 {
			remoteArch = systemParts[0]
			// Remove "(P)" suffix if present
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
		// Pass the workingDir so the console starts in the target session's current directory
		// This prevents session confusion when connecting to multiple remote targets
		// TODO: Persistent working directory is NOT yet available for remote leaf sessions (multi-hop).
		// Currently, uSess.WorkingDir may be empty or stale for leaves because the intermediate gateway
		// does not track/persist the state of transient SFTP channels opened to the leaf.
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
