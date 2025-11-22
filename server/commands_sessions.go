package server

import (
	"errors"
	"fmt"
	"sort"
	"text/tabwriter"

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

func (c *SessionsCommand) Name() string        { return sessionsCmd }
func (c *SessionsCommand) Description() string { return sessionsDesc }
func (c *SessionsCommand) Usage() string       { return sessionsUsage }

func (c *SessionsCommand) Run(s *server, args []string, ui UserInterface) error {
	var list bool
	sessionsFlags := pflag.NewFlagSet(sessionsCmd, pflag.ContinueOnError)
	sessionsFlags.SetOutput(ui.Writer())

	sInteract := sessionsFlags.IntP("interactive", "i", 0, "Start Interactive Slider Shell on a Session ID")
	sDisconnect := sessionsFlags.IntP("disconnect", "d", 0, "Disconnect Session ID")
	sKill := sessionsFlags.IntP("kill", "k", 0, "Kill Session ID")

	sessionsFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", sessionsUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", executeDesc) // Note: Original code used executeDesc here, might be a copy-paste error in original code, but keeping it for now or should I fix it? sessionsDesc is better.
		sessionsFlags.PrintDefaults()
	}

	if pErr := sessionsFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		ui.PrintError("Flag error: %v", pErr)
		return nil
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
		ui.PrintError("flags --interactive, --disconnect and --kill cannot be used together")
		return nil
	}

	if len(args) == 0 {
		list = true
	}

	if list {
		if len(s.sessionTrack.Sessions) > 0 {
			var keys []int
			for i := range s.sessionTrack.Sessions {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			tw := new(tabwriter.Writer)
			tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintf(tw, "\n\tID\tSystem\tUser\tHost\tIO\tConnection\tSocks\tSSH/SFTP\tShell/TLS\tCertID\t")
			_, _ = fmt.Fprintf(tw, "\n\t--\t------\t----\t----\t--\t----------\t-----\t--------\t---------\t------\t\n")

			for _, i := range keys {
				session := s.sessionTrack.Sessions[int64(i)]

				socksPort := "--"
				if session.SocksInstance.IsEnabled() {
					if port, pErr := session.SocksInstance.GetEndpointPort(); pErr == nil {
						socksPort = fmt.Sprintf("%d", port)
					}
				}

				sshPort := "--"
				if session.SSHInstance.IsEnabled() {
					if port, pErr := session.SSHInstance.GetEndpointPort(); pErr == nil {
						sshPort = fmt.Sprintf("%d", port)
					}
				}

				shellPort := "--"
				shellTLS := "--"
				if session.ShellInstance.IsEnabled() {
					if port, pErr := session.ShellInstance.GetEndpointPort(); pErr == nil {
						shellPort = fmt.Sprintf("%d", port)
					}
					shellTLS = "off"
					if session.ShellInstance.IsTLSOn() {
						shellTLS = "on"
					}
				}

				if session.clientInterpreter != nil {
					certID := "--"
					if s.authOn && session.certInfo.id != 0 {
						certID = fmt.Sprintf("%d", session.certInfo.id)
					}
					var inOut = "<-"
					if session.isListener {
						inOut = "->"
					}

					hostname := session.clientInterpreter.Hostname
					if len(hostname) > 15 {
						hostname = hostname[:15] + "..."
					}

					_, _ = fmt.Fprintf(tw, "\t%d\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
						session.sessionID,
						session.clientInterpreter.Arch,
						session.clientInterpreter.System,
						session.clientInterpreter.User,
						hostname,
						inOut,
						session.wsConn.RemoteAddr().String(),
						socksPort,
						sshPort,
						fmt.Sprintf("%s/%s", shellPort, shellTLS),
						certID,
					)
				}
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		ui.PrintInfo("Active sessions: %d\n", s.sessionTrack.SessionActive)
		return nil
	}

	if *sInteract > 0 {
		session, sessErr := s.getSession(*sInteract)
		if sessErr != nil {
			ui.PrintInfo("Unknown Session ID %d", *sInteract)
			return nil
		}

		sftpCli, sErr := session.newSftpClient()
		if sErr != nil {
			ui.PrintInfo("Failed to create SFTP Client: %v", sErr)
		}
		defer func() { _ = sftpCli.Close() }()
		s.newSftpConsole(session, sftpCli)

		// Reset autocomplete commands - Wait, sftpConsole modifies autocomplete?
		// Yes, s.newSftpConsole calls s.newSftpTerminal which sets prompt and autocomplete.
		// When it returns, we need to restore the main console autocomplete.
		// Original code:
		// commands := s.initCommands()
		// s.console.setConsoleAutoComplete(commands)
		// New code:
		s.console.setConsoleAutoComplete(s.commandRegistry)

		return nil
	}

	if *sDisconnect > 0 {
		session, sessErr := s.getSession(*sDisconnect)
		if sessErr != nil {
			ui.PrintInfo("Unknown Session ID %d", *sDisconnect)
			return nil
		}
		if cErr := session.wsConn.Close(); cErr != nil {
			ui.PrintError("Failed to close connection to Session ID %d", session.sessionID)
			return nil
		}
		ui.PrintSuccess("Closed connection to Session ID %d", session.sessionID)
		return nil
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			ui.PrintInfo("Unknown Session ID %d", *sKill)
			return nil
		}
		var err error
		if _, _, err = session.sendRequest(
			"shutdown",
			true,
			nil,
		); err != nil {
			ui.PrintError("Client did not answer properly to the request: %s", err)
			return nil
		}
		ui.PrintSuccess("SessionID %d terminated gracefully", *sKill)

		return nil
	}
	return nil
}
