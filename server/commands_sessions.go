package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"slider/pkg/conf"
	"slider/server/remote"
	"sort"
	"strconv"
	"text/tabwriter"

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
	Extra          string // For port info etc
	IsListener     bool
	ConnectionAddr string
	Path           []int64
}

// ResolveUnifiedSessions aggregates local and remote sessions into a single list with Unified IDs
func (s *server) ResolveUnifiedSessions() map[int64]UnifiedSession {
	unifiedMap := make(map[int64]UnifiedSession)

	maxID := int64(0)

	// 1. Collect Local Sessions
	s.sessionTrackMutex.Lock()
	// Copy sessions to avoid locking during remote calls later
	localSessions := make([]*Session, 0, len(s.sessionTrack.Sessions))
	for _, sess := range s.sessionTrack.Sessions {
		localSessions = append(localSessions, sess)
	}
	s.sessionTrackMutex.Unlock()

	for _, sess := range localSessions {
		uSess := UnifiedSession{
			UnifiedID: sess.sessionID,
			ActualID:  sess.sessionID,
			OwnerID:   0,
			User:      "unknown",
			Host:      "unknown",
			System:    "unknown",
		}

		if sess.sessionID > maxID {
			maxID = sess.sessionID
		}

		if sess.sshClient != nil {
			uSess.Type = "PROMISCUOUS/SERVER"
			uSess.User = "server"
			uSess.Host = sess.wsConn.RemoteAddr().String()
			uSess.System = "unknown/unknown (P)"
			if sess.clientInterpreter != nil {
				uSess.User = sess.clientInterpreter.User
				uSess.Host = sess.clientInterpreter.Hostname
				uSess.System = fmt.Sprintf("%s/%s (P)", sess.clientInterpreter.Arch, sess.clientInterpreter.System)
			}
		} else if sess.clientInterpreter != nil {
			uSess.User = sess.clientInterpreter.User
			uSess.Host = sess.clientInterpreter.Hostname
			uSess.System = fmt.Sprintf("%s/%s", sess.clientInterpreter.Arch, sess.clientInterpreter.System)
			uSess.Type = "LOCAL"
		}

		unifiedMap[uSess.UnifiedID] = uSess
	}

	// 2. Collect Remote Sessions
	// Iterate only over Promiscuous Clients (Gateways)
	for _, sess := range localSessions {
		if sess.sshClient != nil {
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
						OwnerID:        sess.sessionID, // This local session is the gateway
						Type:           "REMOTE",
						User:           rs.User,
						Host:           rs.Host,
						System:         system,
						IsListener:     rs.IsListener,
						ConnectionAddr: rs.ConnectionAddr,
						Path:           rs.Path, // Path from the remote perspective (relative to Owner)
					}
					unifiedMap[uSess.UnifiedID] = uSess
				}
			}
		}
	}

	return unifiedMap
}

func (c *SessionsCommand) Name() string        { return sessionsCmd }
func (c *SessionsCommand) Description() string { return sessionsDesc }
func (c *SessionsCommand) Usage() string       { return sessionsUsage }

func (c *SessionsCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
	ui := ctx.UI()

	var list bool
	sessionsFlags := pflag.NewFlagSet(sessionsCmd, pflag.ContinueOnError)
	sessionsFlags.SetOutput(ui.Writer())

	sInteract := sessionsFlags.StringP("interactive", "i", "", "Start Interactive Slider Shell on a Session ID")
	sDisconnect := sessionsFlags.StringP("disconnect", "d", "", "Disconnect Session ID")
	sKill := sessionsFlags.StringP("kill", "k", "", "Kill Session ID")

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
		unifiedMap := server.ResolveUnifiedSessions()

		if len(unifiedMap) > 0 {
			var keys []int
			for k := range unifiedMap {
				keys = append(keys, int(k))
			}
			sort.Ints(keys)

			tw := new(tabwriter.Writer)
			tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
			// Added Owner column
			_, _ = fmt.Fprintf(tw, "\n\tID\tOwner\tSystem\tUser\tHost\tIO\tConnection\tSocks\tSSH/SFTP\tShell/TLS\tCertID\t")
			_, _ = fmt.Fprintf(tw, "\n\t--\t-----\t------\t----\t----\t--\t----------\t-----\t--------\t---------\t------\t\n")

			for _, i := range keys {
				uSess := unifiedMap[int64(i)]

				// Defaults for Remote
				socksPort := "--"
				sshPort := "--"
				shellPort := "--"
				shellTLS := "--"
				certID := "--"
				inOut := "--"
				connection := "--"

				// If Local, fetch detailed info from actual session
				if uSess.OwnerID == 0 {
					if session, ok := server.sessionTrack.Sessions[uSess.ActualID]; ok {
						if session.SocksInstance.IsEnabled() {
							if port, pErr := session.SocksInstance.GetEndpointPort(); pErr == nil {
								socksPort = fmt.Sprintf("%d", port)
							}
						}
						if session.SSHInstance.IsEnabled() {
							if port, pErr := session.SSHInstance.GetEndpointPort(); pErr == nil {
								sshPort = fmt.Sprintf("%d", port)
							}
						}
						if session.ShellInstance.IsEnabled() {
							if port, pErr := session.ShellInstance.GetEndpointPort(); pErr == nil {
								shellPort = fmt.Sprintf("%d", port)
							}
							shellTLS = "off"
							if session.ShellInstance.IsTLSOn() {
								shellTLS = "on"
							}
						}
						if server.authOn && session.certInfo.id != 0 {
							certID = fmt.Sprintf("%d", session.certInfo.id)
						}
						inOut = "<-"
						if session.isListener {
							inOut = "->"
						}
						connection = session.wsConn.RemoteAddr().String()
					}
				} else {
					// Remote Session Logic
					// Set IO and Connection from remote session info
					inOut = "<-"
					if uSess.IsListener {
						inOut = "->"
					}
					connection = uSess.ConnectionAddr

					// Check for SOCKS
					socksKey := fmt.Sprintf("socks:%d:%v", uSess.OwnerID, uSess.Path)
					server.remoteSessionsMutex.Lock()
					if state, ok := server.remoteSessions[socksKey]; ok {
						if state.SocksInstance != nil && state.SocksInstance.IsEnabled() {
							if port, pErr := state.SocksInstance.GetEndpointPort(); pErr == nil {
								socksPort = fmt.Sprintf("%d", port)
							}
						}
					}
					server.remoteSessionsMutex.Unlock()

					// Check for SSH
					sshKey := fmt.Sprintf("ssh:%d:%v", uSess.OwnerID, uSess.Path)
					server.remoteSessionsMutex.Lock()
					if state, ok := server.remoteSessions[sshKey]; ok {
						if state.SSHInstance != nil && state.SSHInstance.IsEnabled() {
							if port, pErr := state.SSHInstance.GetEndpointPort(); pErr == nil {
								sshPort = fmt.Sprintf("%d", port)
							}
						}
					}
					server.remoteSessionsMutex.Unlock()
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
					uSess.User,
					hostname,
					inOut,
					connection,
					socksPort,
					sshPort,
					fmt.Sprintf("%s/%s", shellPort, shellTLS),
					certID,
				)
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		ui.PrintInfo("Active sessions: %d\n", server.sessionTrack.SessionActive)
		return nil
	}

	if *sInteract != "" {
		// Parse Unified ID
		uID, err := strconv.ParseInt(*sInteract, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid session ID: %s (must be integer)", *sInteract)
		}

		unifiedMap := server.ResolveUnifiedSessions()
		uSess, ok := unifiedMap[uID]
		if !ok {
			return fmt.Errorf("session %d not found", uID)
		}

		// ROUTE BASED ON LOCAL vs REMOTE
		if uSess.OwnerID == 0 {
			// LOCAL SESSION
			session, sessErr := server.getSession(int(uSess.ActualID))
			if sessErr != nil {
				return fmt.Errorf("unknown local session ID %d", uSess.ActualID)
			}

			sftpCli, sErr := session.newSftpClient()
			if sErr != nil {
				return fmt.Errorf("failed to create SFTP client: %w", sErr)
			}
			defer func() { _ = sftpCli.Close() }()

			console, ok := ui.(*Console)
			if !ok {
				return fmt.Errorf("UI is not a Console")
			}
			server.newSftpConsole(console, session, sftpCli)
			console.setConsoleAutoComplete(server.commandRegistry)
			return nil
		} else {
			// REMOTE SESSION
			// 1. Get Gateway Session
			gatewaySession, sessErr := server.getSession(int(uSess.OwnerID))
			if sessErr != nil {
				return fmt.Errorf("gateway session %d not found (disconnected?)", uSess.OwnerID)
			}

			if gatewaySession.sshClient == nil {
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

			sftpChan, reqs, err := gatewaySession.sshClient.OpenChannel("slider-connect", payload)
			if err != nil {
				return fmt.Errorf("failed to open remote channel to %s: %v", target, err)
			}
			go func() {
				for req := range reqs {
					switch req.Type {
					case "keep-alive":
						_ = gatewaySession.replyConnRequest(req, true, []byte("pong"))
					case "client-info":
						ci := &conf.ClientInfo{}
						if jErr := json.Unmarshal(req.Payload, ci); jErr == nil {
							gatewaySession.setInterpreter(ci.Interpreter)
						}
						_ = gatewaySession.replyConnRequest(req, true, nil)
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
			defer func() { _ = sftpCli.Close() }()

			console, ok := ui.(*Console)
			if !ok {
				return fmt.Errorf("UI is not a Console")
			}

			server.newSftpConsole(console, gatewaySession, sftpCli)
			console.setConsoleAutoComplete(server.commandRegistry)
			return nil
		}
	}

	if *sDisconnect != "" {
		if id, err := strconv.Atoi(*sDisconnect); err == nil {
			session, sessErr := server.getSession(id)
			if sessErr != nil {
				return fmt.Errorf("unknown session ID %d", id)
			}
			if cErr := session.wsConn.Close(); cErr != nil {
				return fmt.Errorf("failed to close connection to session ID %d: %w", session.sessionID, cErr)
			}
			ui.PrintSuccess("Closed connection to Session ID %d", session.sessionID)
			return nil
		}
		return fmt.Errorf("remote session disconnect not implemented yet")
	}

	if *sKill != "" {
		if id, err := strconv.Atoi(*sKill); err == nil {
			session, sessErr := server.getSession(id)
			if sessErr != nil {
				return fmt.Errorf("unknown session ID %d", id)
			}
			var err error
			if _, _, err = session.sendRequest(
				"shutdown",
				true,
				nil,
			); err != nil {
				return fmt.Errorf("client did not answer properly to the request: %w", err)
			}
			ui.PrintSuccess("SessionID %d terminated gracefully", id)

			return nil
		}
		return fmt.Errorf("remote session kill not implemented yet")
	}
	return nil
}
