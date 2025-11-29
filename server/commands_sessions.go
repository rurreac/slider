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

func (c *SessionsCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
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
		if len(server.sessionTrack.Sessions) > 0 {
			var keys []int
			for i := range server.sessionTrack.Sessions {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			tw := new(tabwriter.Writer)
			tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintf(tw, "\n\tID\tSystem\tUser\tHost\tIO\tConnection\tSocks\tSSH/SFTP\tShell/TLS\tCertID\t")
			_, _ = fmt.Fprintf(tw, "\n\t--\t------\t----\t----\t--\t----------\t-----\t--------\t---------\t------\t\n")

			for _, i := range keys {
				session := server.sessionTrack.Sessions[int64(i)]

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
					if server.authOn && session.certInfo.id != 0 {
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
		ui.PrintInfo("Active sessions: %d\n", server.sessionTrack.SessionActive)
		return nil
	}

	if *sInteract > 0 {
		session, sessErr := server.getSession(*sInteract)
		if sessErr != nil {
			return fmt.Errorf("unknown session ID %d", *sInteract)
		}

		sftpCli, sErr := session.newSftpClient()
		if sErr != nil {
			return fmt.Errorf("failed to create SFTP client: %w", sErr)
		}
		defer func() { _ = sftpCli.Close() }()
		server.newSftpConsole(session, sftpCli)

		// Reset autocomplete commands
		server.console.setConsoleAutoComplete(server.commandRegistry)

		return nil
	}

	if *sDisconnect > 0 {
		session, sessErr := server.getSession(*sDisconnect)
		if sessErr != nil {
			return fmt.Errorf("unknown session ID %d", *sDisconnect)
		}
		if cErr := session.wsConn.Close(); cErr != nil {
			return fmt.Errorf("failed to close connection to session ID %d: %w", session.sessionID, cErr)
		}
		ui.PrintSuccess("Closed connection to Session ID %d", session.sessionID)
		return nil
	}

	if *sKill > 0 {
		session, sessErr := server.getSession(*sKill)
		if sessErr != nil {
			return fmt.Errorf("unknown session ID %d", *sKill)
		}
		var err error
		if _, _, err = session.sendRequest(
			"shutdown",
			true,
			nil,
		); err != nil {
			return fmt.Errorf("client did not answer properly to the request: %w", err)
		}
		ui.PrintSuccess("SessionID %d terminated gracefully", *sKill)

		return nil
	}
	return nil
}
