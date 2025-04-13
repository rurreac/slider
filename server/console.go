package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/sflag"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

type Console struct {
	Term      *term.Terminal
	InitState *term.State
	Output    *log.Logger
	FirstRun  bool
}

func (s *server) consoleBanner() {
	s.console.clearScreen()
	s.console.Printf("%s%s%s\n\n", greyBold, conf.Banner, resetColor)
	s.console.PrintlnDebugStep("Type \"bg\" or press CTRL^C again to return to logging.")
	s.console.PrintlnDebugStep("Type \"help\" to see available commands.")
	s.console.PrintlnDebugStep("Type \"exit\" to exit the console.\n")

}

func (s *server) NewConsole() string {
	var out string

	// Set Console Colors
	setConsoleColors()

	// Get available Commands
	commands := s.initCommands()

	// Initialize Term
	var rErr error
	// Not Initializing with os.Stdin will fail on Windows
	s.console.InitState, rErr = term.MakeRaw(int(os.Stdin.Fd()))
	if rErr != nil {
		s.Logger.Fatalf("Failed to initialize terminal: %s", rErr)
		return exitCmd
	}
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.console.InitState)
	}()

	screen := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	// Set Console
	s.console.Term = term.NewTerminal(screen, getPrompt())

	// Disabling autocompletion if not PTY as tabs won't the handled properly
	if s.serverInterpreter.PtyOn {
		s.console.setConsoleAutoComplete(commands)
	}

	s.console.Output = log.New(s.console.Term, "", 0)

	// Set Console
	if width, height, tErr := term.GetSize(int(os.Stdout.Fd())); tErr == nil {
		// Disregard the error if fails setting Console size
		_ = s.console.Term.SetSize(width, height)
	}

	if s.console.FirstRun {
		s.consoleBanner()
		s.console.FirstRun = false
	}

	for consoleInput := true; consoleInput; {
		var fCmd string
		input, err := s.console.Term.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.console.TermPrintf("\rFailed to read input: %s\r\n", err)
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF
			// We will background gracefully when this happens
			s.console.PrintlnInfo("\n\rLogging...\n")
			return bgCmd
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)

		if len(args) > 0 {
			fCmd = args[0]
		}

		switch fCmd {
		case exitCmd, bgCmd:
			out = fCmd
			if out == bgCmd {
				s.console.PrintlnInfo("Logging...\n\r")
			}
			consoleInput = false
		case helpCmd:
			s.printConsoleHelp()
		case "":
			continue
		default:
			currentPrompt := getPrompt()
			if k, ok := commands[fCmd]; ok {
				k.cmdFunc(args[1:]...)
			} else {
				s.notConsoleCommand(args)
			}
			s.console.Term.SetPrompt(currentPrompt)
		}
	}

	return out
}

func (c *Console) setConsoleAutoComplete(commands map[string]commandStruct) {
	// List of the Ordered the commands for autocompletion
	var cmdList []string
	for k := range commands {
		cmdList = append(cmdList, k)
	}
	slices.Sort(cmdList)
	// Simple autocompletion
	c.Term.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		// If TAB key is pressed and text was written
		if key == 9 && len(line) > 0 {
			newLine, newPos := autocompleteCommand(line, cmdList)
			return newLine, newPos, true
		}
		return line, pos, false
	}
}

func autocompleteCommand(input string, cmdList []string) (string, int) {
	var cmd string
	var substring string
	var count int

	for _, c := range cmdList {
		if strings.HasPrefix(c, input) {
			cmd = c
			substring = strings.SplitAfter(c, input)[0]
			count++
		} else if count == 1 {
			return cmd, len(cmd)
		}
	}

	if count == 1 {
		return cmd, len(cmd)
	}

	if count == 0 {
		substring = input
	}

	return substring, len(substring)
}

func (s *server) notConsoleCommand(fCmd []string) {
	s.console.PrintlnWarnStep("Console does not recognize Command: %s", fCmd)

	// If a Shell was not set just return
	if s.serverInterpreter.Shell == "" {
		return
	}

	// Else, we'll try to execute the command locally
	s.console.PrintlnDebugStep("Will run an OS command locally instead...")
	fCmd = append(s.serverInterpreter.CmdArgs, strings.Join(fCmd, " "))

	cmd := exec.Command(s.serverInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Stdout = s.console.Term
	cmd.Stderr = s.console.Term
	if err := cmd.Run(); err != nil {
		s.console.PrintlnErrorStep("%v", err)
	}
	s.console.Println("")

}

func (s *server) executeCommand(args ...string) {
	executeFlags := sflag.NewFlagPack([]string{executeCmd}, executeUsage, executeDesc, s.console.Term)
	eSession, _ := executeFlags.NewIntFlag("s", "session", "Run command passed as an argument on a session id", 0)
	eAll, _ := executeFlags.NewBoolFlag("a", "all", "Run command passed as an argument on all sessions", false)
	executeFlags.Set.Usage = func() {
		executeFlags.PrintUsage(true)
	}

	if pErr := executeFlags.Set.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 || (*eAll && *eSession > 0) || (!*eAll && *eSession == 0) {
		executeFlags.Set.Usage()
		return
	}

	if len(executeFlags.Set.Args()) == 0 {
		s.console.PrintlnErrorStep("Nothing to execute")
		return
	}

	var sessions []*Session
	if *eSession > 0 {
		session, sessErr := s.getSession(*eSession)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *eSession)
			return
		}
		sessions = []*Session{session}
	}

	if *eAll {
		for _, session := range s.sessionTrack.Sessions {
			sessions = append(sessions, session)
		}
	}

	for _, session := range sessions {
		if *eAll {
			s.console.PrintWarnSelect(
				"Executing Command on ",
				fmt.Sprintf("SessionID %d", session.sessionID),
			)
		}

		command := strings.Join(executeFlags.Set.Args(), " ")
		var envVarList []struct{ Key, Value string }

		instance := session.newExecInstance(envVarList)

		if err := instance.ExecuteCommand(command, s.console.InitState); err != nil {
			s.console.PrintlnErrorStep("%v", err)
		}
		s.console.Println("")
	}
}

func (s *server) sessionsCommand(args ...string) {
	var list bool
	sessionsFlags := sflag.NewFlagPack([]string{sessionsCmd}, sessionsUsage, executeDesc, s.console.Term)
	sInteract, _ := sessionsFlags.NewIntFlag("i", "interactive", "Start Interactive Slider Shell on a Session ID", 0)
	sDisconnect, _ := sessionsFlags.NewIntFlag("d", "disconnect", "Disconnect Session ID", 0)
	sKill, _ := sessionsFlags.NewIntFlag("k", "kill", "Kill Session ID", 0)
	sessionsFlags.Set.Usage = func() {
		sessionsFlags.PrintUsage(true)
	}

	if pErr := sessionsFlags.Set.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 {
		list = true
	}

	if !list && ((*sInteract > 0 && *sKill > 0 && *sDisconnect > 0) || (*sInteract == 0 && *sKill == 0 && *sDisconnect == 0)) {
		s.console.Output.Printf("Flags '-i', '-d' and '-k' are mutually exclusive, nor can have 0 value.")
		return
	}

	if sessionsFlags.Set.NArg() > 0 {
		s.console.TermPrintf("Unexpected arguments: %s", sessionsFlags.Set.Args())
		sessionsFlags.PrintUsage(true)
		return
	}

	var err error

	if list {
		if len(s.sessionTrack.Sessions) > 0 {
			var keys []int
			for i := range s.sessionTrack.Sessions {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			tw := new(tabwriter.Writer)
			tw.Init(s.console.Term, 0, 4, 2, ' ', 0)
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
		s.console.PrintlnDebugStep("Active sessions: %d\n", s.sessionTrack.SessionActive)
		return
	}

	if *sInteract > 0 {
		session, sessErr := s.getSession(*sInteract)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sInteract)
			return
		}

		sftpCli, sErr := session.newSftpClient()
		if sErr != nil {
			s.console.PrintlnDebugStep("Failed to create SFTP Client: %v", sErr)
		}
		defer func() { _ = sftpCli.Close() }()
		s.newSftpConsole(session, sftpCli)

		// Reset autocomplete commands
		commands := s.initCommands()
		s.console.setConsoleAutoComplete(commands)

		return
	}

	if *sDisconnect > 0 {
		session, sessErr := s.getSession(*sDisconnect)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sDisconnect)
			return
		}
		if cErr := session.wsConn.Close(); cErr != nil {
			s.console.PrintlnErrorStep("Failed to close connection to Session ID %d", session.sessionID)
			return
		}
		s.console.PrintlnOkStep("Closed connection to Session ID %d", session.sessionID)
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sKill)
			return
		}
		if _, _, err = session.sendRequest(
			"shutdown",
			true,
			nil,
		); err != nil {
			s.console.PrintlnErrorStep("Client did not answer properly to the request: %s", err)
			return
		}
		s.console.PrintlnOkStep("SessionID %d terminated gracefully", *sKill)

		return
	}
}

func (s *server) socksCommand(args ...string) {
	socksFlags := sflag.NewFlagPack([]string{socksCmd}, socksUsage, socksDesc, s.console.Term)
	sSession, _ := socksFlags.NewIntFlag("s", "session", "Run a Socks5 server over an SSH Channel on a Session ID", 0)
	sPort, _ := socksFlags.NewIntFlag("p", "port", "Use this port number as local Listener, otherwise randomly selected", 0)
	sKill, _ := socksFlags.NewIntFlag("k", "kill", "Kill Socks5 Listener and Server on a Session ID", 0)
	sExpose, _ := socksFlags.NewBoolFlag("e", "expose", "Expose port to all interfaces", false)
	socksFlags.Set.Usage = func() {
		socksFlags.PrintUsage(true)
	}

	if pErr := socksFlags.Set.Parse(args); pErr != nil {
		return
	}

	var session *Session
	var sessErr error
	if (*sSession == 0 && *sKill == 0) || (*sSession > 0 && *sKill > 0) {
		socksFlags.PrintUsage(true)
		return
	} else {
		sessionID := *sSession + *sKill
		session, sessErr = s.getSession(sessionID)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
			return
		}
	}

	if *sExpose && *sKill != 0 {
		s.console.PrintlnDebugStep("Flag '-e' is not compatible with '-k'")
		socksFlags.PrintUsage(true)
		return
	}

	if *sKill > 0 {
		if session.SocksInstance.IsEnabled() {
			if err := session.SocksInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return
			}
			s.console.PrintlnOkStep("Socks Endpoint gracefully stopped")
			return
		}
		s.console.PrintlnDebugStep("No Socks Server on Session ID %d", *sKill)
		return
	}

	if *sSession > 0 {
		if session.SocksInstance.IsEnabled() {
			if port, pErr := session.SocksInstance.GetEndpointPort(); pErr == nil {
				s.console.PrintlnErrorStep("Socks Endpoint already running on port: %d", port)
			}
			return
		}
		s.console.PrintlnDebugStep("Enabling Socks Endpoint in the background")

		go session.socksEnable(*sPort, *sExpose)

		// Give some time to check
		socksTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)
		for range socksTicker.C {
			if time.Now().Before(timeout) {
				port, sErr := session.SocksInstance.GetEndpointPort()
				if port == 0 || sErr != nil {
					fmt.Printf(".")
					continue
				}
				s.console.PrintlnOkStep("Socks Endpoint running on port: %d", port)
				return
			}
			s.console.PrintlnErrorStep("Socks Endpoint timeout, port likely in use")
			return
		}
	}

	socksFlags.PrintUsage(true)
}

func (s *server) certsCommand(args ...string) {
	certsFlags := sflag.NewFlagPack([]string{certsCmd}, certsUsage, certsDesc, s.console.Term)
	cNew, _ := certsFlags.NewBoolFlag("n", "new", "Generate a new Key Pair", false)
	cRemove, _ := certsFlags.NewIntFlag("r", "remove", "Remove matching index from the Certificate Jar", 0)
	cSSH, _ := certsFlags.NewIntFlag("d", "dump", "Dump CertID SSH keys", 0)
	certsFlags.Set.Usage = func() {
		certsFlags.PrintUsage(true)
	}
	if err := certsFlags.Set.Parse(args); err != nil {
		return
	}

	if (*cNew && *cRemove != 0) || (*cNew && *cSSH != 0) || (*cRemove != 0 && *cSSH != 0) {
		s.console.TermPrintf("Flags '-n', '-k' and '-s' are mutually exclusive\n")
		return
	}

	twl := new(tabwriter.Writer)
	twl.Init(s.console.Term, 0, 4, 2, ' ', 0)

	// If no flags are set, list all certificates
	if (!*cNew && *cRemove == 0 && *cSSH == 0) || (len(args) == 0) {
		if len(s.certTrack.Certs) > 0 {
			var keys []int
			for i := range s.certTrack.Certs {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			for _, k := range keys {
				_, _ = fmt.Fprintln(twl)
				_, _ = fmt.Fprintf(twl, "\tCertID %d\n\t%s\n",
					k,
					strings.Repeat("-", 11),
				)
				_, _ = fmt.Fprintf(twl, "\tPrivate Key:\t%s\t\n", s.certTrack.Certs[int64(k)].PrivateKey)
				_, _ = fmt.Fprintf(twl, "\tFingerprint:\t%s\t\n", s.certTrack.Certs[int64(k)].FingerPrint)
				sessionList := "None"
				if sl := s.getSessionsByCertID(int64(k)); len(sl) > 0 {
					sessionListStr := make([]string, 0)
					for i := range sl {
						sStr := fmt.Sprintf("%d", sl[i])
						sessionListStr = append(sessionListStr, sStr)
					}
					sessionList = strings.Join(sessionListStr, ", ")
				}
				_, _ = fmt.Fprintf(twl, "\tUsed by Session:\t%s\t\n", sessionList)
			}
			_, _ = fmt.Fprintln(twl)
			_ = twl.Flush()
		}
		s.console.PrintlnDebugStep("Certificates in Jar: %d\n", s.certTrack.CertActive)
		return
	}

	if *cSSH != 0 {
		if keyPair, err := s.getCert(int64(*cSSH)); err == nil {
			if s.certSaveOn {
				if keyPath, pErr := s.savePrivateKey(int64(*cSSH)); pErr != nil {
					s.console.PrintlnErrorStep("Failed to save private key - %s", pErr)
				} else {
					s.console.PrintlnOkStep("Private Key saved to %s", keyPath)
				}
				if keyPath, pErr := s.savePublicKey(int64(*cSSH)); pErr != nil {
					s.console.PrintlnErrorStep("Failed to save private key - %s", pErr)
				} else {
					s.console.PrintlnOkStep("Private Key saved to %s", keyPath)
				}
				return
			}
			s.console.PrintlnOkStep("SSH Private Key\n%s", keyPair.SSHPrivateKey)
			s.console.PrintlnOkStep("SSH Public Key\n%s", keyPair.SSHPublicKey)
			return
		}
		s.console.PrintlnErrorStep("Certificate ID %d not found", *cSSH)
		return
	}

	if *cNew {
		keypair, err := s.newCertItem()
		if err != nil {
			s.console.PrintlnErrorStep("Failed to generate certificate - %s", err)
		}
		twn := new(tabwriter.Writer)
		twn.Init(s.console.Term, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(twn)
		_, _ = fmt.Fprintf(twn, "\tPrivate Key:\t%s\t\n", keypair.PrivateKey)
		_, _ = fmt.Fprintf(twn, "\tFingerprint:\t%s\t\n", keypair.FingerPrint)
		_, _ = fmt.Fprintln(twn)
		_ = twn.Flush()
		return
	}

	if *cRemove > 0 {
		if err := s.dropCertItem(int64(*cRemove)); err != nil {
			s.console.PrintlnErrorStep("%s", err)
			return
		}
		s.console.PrintlnOkStep("Certificate successfully removed")
		return
	}
}

func (s *server) connectCommand(args ...string) {
	connectFlags := sflag.NewFlagPack([]string{connectCmd}, connectUsage, connectDesc, s.console.Term)
	cCert, _ := connectFlags.NewInt64Flag("c", "cert", "Specify certID for key authentication", 0)
	cDNS, _ := connectFlags.NewStringFlag("d", "dns", "Use custom DNS resolver", "")
	connectFlags.Set.Usage = func() {
		connectFlags.PrintUsage(true)
	}
	if err := connectFlags.Set.Parse(args); err != nil {
		return
	}
	if len(connectFlags.Set.Args()) == 0 || len(connectFlags.Set.Args()) > 1 {
		connectFlags.PrintUsage(true)
		return
	}
	clientURL := connectFlags.Set.Args()[0]
	cu, uErr := conf.ResolveURL(clientURL)
	if uErr != nil {
		s.console.PrintlnErrorStep("Failed to resolve URL: %v", uErr)
		return
	}

	s.console.PrintlnDebugStep("Establishing Connection to %s (Timeout: %s)", cu.String(), conf.Timeout)

	notifier := make(chan bool, 1)
	timeout := time.Now().Add(conf.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)

	go s.newClientConnector(cu, notifier, *cCert, *cDNS)

	for {
		select {
		case connected := <-notifier:
			if connected {
				s.console.PrintlnOkStep("Successfully connected to Client")
				close(notifier)
				return
			} else {
				s.console.PrintlnErrorStep("Failed to connect to Client")
				close(notifier)
				return
			}
		case t := <-ticker.C:
			if t.After(timeout) {
				s.console.PrintlnErrorStep("Timed out connecting to Client")
				close(notifier)
				return
			}
		}
	}
}

func (s *server) sshCommand(args ...string) {
	sshFlags := sflag.NewFlagPack([]string{sshCmd}, sshUsage, sshDesc, s.console.Term)
	sSession, _ := sshFlags.NewIntFlag("s", "sesssion", "Session ID to establish SSH connection with", 0)
	sPort, _ := sshFlags.NewIntFlag("p", "port", "Local port to forward SSH connection to", 0)
	sKill, _ := sshFlags.NewIntFlag("k", "kill", "Kill SSH port forwarding to a Session ID", 0)
	sExpose, _ := sshFlags.NewBoolFlag("e", "expose", "Expose port to all interfaces", false)
	sshFlags.Set.Usage = func() {
		sshFlags.PrintUsage(true)
	}

	if pErr := sshFlags.Set.Parse(args); pErr != nil {
		return
	}

	var session *Session
	var sessErr error
	if (*sSession == 0 && *sKill == 0) || (*sSession > 0 && *sKill > 0) {
		s.console.PrintlnDebugStep("Session ID is required")
		sshFlags.PrintUsage(true)
		return
	} else {
		sessionID := *sSession + *sKill
		session, sessErr = s.getSession(sessionID)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
			return
		}
	}

	if *sExpose && *sKill != 0 {
		s.console.PrintlnDebugStep("Flag '-e' is not compatible with '-k'")
		sshFlags.PrintUsage(true)
		return
	}

	if *sKill > 0 {
		if session.SSHInstance.IsEnabled() {
			if err := session.SSHInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return
			}
			s.console.PrintlnOkStep("SSH Endpoint gracefully stopped")
			return
		}
		s.console.PrintlnDebugStep("No SSH Endpoint on Session ID %d", *sKill)
		return
	}

	if *sSession > 0 {
		if session.SSHInstance.IsEnabled() {
			if port, pErr := session.SSHInstance.GetEndpointPort(); pErr == nil {
				s.console.PrintlnErrorStep("SSH Endpoint already running on port: %d", port)
			}
			return
		}
		s.console.PrintlnDebugStep("Enabling SSH Endpoint in the background")

		go session.sshEnable(*sPort, *sExpose)

		// Give some time to check
		sshTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)
		for range sshTicker.C {
			if time.Now().Before(timeout) {
				port, sErr := session.SSHInstance.GetEndpointPort()
				if port == 0 || sErr != nil {
					fmt.Printf(".")
					continue
				}
				s.console.PrintlnOkStep("SSH Endpoint running on port: %d", port)
				return
			}
			s.console.PrintlnErrorStep("SSH Endpoint timeout, port likely in use")
			return
		}
	}

	sshFlags.PrintUsage(true)
}

func (s *server) shellCommand(args ...string) {
	flagPack := sflag.NewFlagPack([]string{shellCmd}, shellUsage, shellDesc, s.console.Term)
	sSession, _ := flagPack.NewIntFlag("s", "session", "Run a Shell server over an SSH Channel on a Session ID", 0)
	sPort, _ := flagPack.NewIntFlag("p", "port", "Use this port number as local Listener, otherwise randomly selected", 0)
	sKill, _ := flagPack.NewIntFlag("k", "kill", "Kill Shell Listener and Server on a Session ID", 0)
	sInteractive, _ := flagPack.NewBoolFlag("i", "interactive", "Interactive mode, enters shell directly. Always TLS", false)
	sTls, _ := flagPack.NewBoolFlag("t", "tls", "Enable TLS for the Shell", false)
	sExpose, _ := flagPack.NewBoolFlag("e", "expose", "Expose port to all interfaces", false)
	flagPack.Set.Usage = func() {
		flagPack.PrintUsage(true)
	}
	if pErr := flagPack.Set.Parse(args); pErr != nil {
		return
	}

	var session *Session
	var sessErr error
	if (*sSession == 0 && *sKill == 0) || (*sSession > 0 && *sKill > 0) {
		flagPack.PrintUsage(true)
		return
	} else {
		sessionID := *sSession + *sKill
		session, sessErr = s.getSession(sessionID)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
			return
		}
	}

	if *sExpose && *sKill != 0 {
		s.console.PrintlnDebugStep("Flag '-e' is not compatible with '-k'")
		flagPack.PrintUsage(true)
		return
	}

	if *sExpose && *sInteractive {
		s.console.PrintlnDebugStep("Flag '-e' ineffective with '-i', Shell won't be exposed")
	}

	if *sInteractive {
		*sTls = true
	}

	if *sKill > 0 {
		if session.ShellInstance.IsEnabled() {
			if err := session.ShellInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return
			}
			s.console.PrintlnOkStep("Shell Endpoint gracefully stopped")
			return
		}
		s.console.PrintlnDebugStep("No Shell Server on Session ID %d", *sKill)
		return
	}

	if *sSession > 0 {
		if session.ShellInstance.IsEnabled() {
			if port, pErr := session.ShellInstance.GetEndpointPort(); pErr == nil {
				s.console.PrintlnErrorStep("Shell Endpoint already running on port: %d", port)
			}
			return
		}
		s.console.PrintlnDebugStep("Enabling Shell Endpoint in the background")

		go session.shellEnable(*sPort, *sExpose, *sTls, *sInteractive)

		// Give some time to check
		var port int
		var sErr error
		shellTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)
		for range shellTicker.C {
			if !time.Now().Before(timeout) {
				s.console.PrintlnErrorStep("Shell Endpoint timeout, port likely in use")
				return
			}
			port, sErr = session.ShellInstance.GetEndpointPort()
			if port == 0 || sErr != nil {
				fmt.Printf(".")
				continue
			} else {
				break
			}
		}
		s.console.PrintlnOkStep("Shell Endpoint running on port: %d", port)

		if *sInteractive {
			var conn net.Conn
			var dErr error

			// When Shell is interactive we want it to stop once we are done
			defer func() {
				if ssErr := session.ShellInstance.Stop(); ssErr != nil {
					session.Logger.Errorf("Failed to stop shell session: %v", ssErr)
				}
				s.console.PrintlnOkStep("Shell Endpoint gracefully stopped\n")
			}()

			// Generate certificate and establish connection
			cert, ccErr := s.CertificateAuthority.CreateCertificate(false)
			if ccErr != nil {
				s.console.PrintlnErrorStep("Failed to create Client TLS certificate - %v", ccErr)
				return
			}
			tlsConfig := s.CertificateAuthority.GetTLSClientConfig(cert)

			conn, dErr = tls.Dial(
				"tcp",
				fmt.Sprintf("127.0.0.1:%d", port),
				tlsConfig,
			)
			if dErr != nil {
				s.console.PrintlnErrorStep("Failed to bind to port %d - %v", port, dErr)
				return
			}
			s.console.PrintlnOkStep("Authenticated with mTLS")

			// Set up the terminal according to the client
			if session.IsPtyOn() {
				s.console.PrintlnOkStep("Shell has PTY, switching to raw terminal")
				tState, tErr := term.MakeRaw(int(os.Stdin.Fd()))
				if tErr != nil {
					s.console.PrintlnErrorStep("Failed to get terminal state, aborting to avoid inconsistent shell")
					return
				}
				defer func() {
					if rErr := term.Restore(int(os.Stdin.Fd()), tState); rErr != nil {
						session.Logger.Errorf("Failed to restore terminal state - %v", rErr)
					}
				}()
			} else {
				s.console.PrintlnDebugStep("Client does not support PTY, terminal not raw, echo is enabled")

				conState, _ := term.GetState(int(os.Stdin.Fd()))
				if rErr := term.Restore(int(os.Stdin.Fd()), s.console.InitState); rErr != nil {
					s.console.PrintlnErrorStep("Failed to revert console state, aborting to avoid inconsistent shell")
					return
				}
				defer func() { _ = term.Restore(int(os.Stdin.Fd()), conState) }()

				// Capture interrupt signals and close the connection cause this terminal doesn't know how to handle them
				go func() {
					sig := make(chan os.Signal, 1)
					signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
					for range sig {
						// Stop capture
						signal.Stop(sig)
						close(sig)
						if cErr := conn.Close(); cErr != nil {
							session.Logger.Errorf("Failed to close Shell connection - %v", cErr)
						}
					}
					s.console.PrintlnWarn("Forcing connection close, press ENTER to continue...")
				}()
			}

			// Clear screen (Windows Command Prompt already does that)
			if string(session.clientInterpreter.System) != "windows" {
				s.console.clearScreen()
			}
			go func() {
				_, _ = io.Copy(os.Stdout, conn)
				s.console.PrintlnWarn("Press ENTER twice to get back to console")
			}()
			_, _ = io.Copy(conn, os.Stdin)

			return
		} else {
			return
		}
	}

	flagPack.PrintUsage(true)
}
