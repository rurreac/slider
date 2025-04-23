package server

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/sflag"
	"slider/pkg/types"
	"sort"
	"strconv"
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

type screenIO struct {
	io.Reader
	io.Writer
}

func (s *server) consoleBanner() {
	s.console.clearScreen()
	s.console.Printf("%s%s%s\n\n", greyBold, conf.Banner, resetColor)
	s.console.PrintlnDebugStep("Type \"bg\" to return to logging.")
	s.console.PrintlnDebugStep("Type \"help\" to see available commands.")
	s.console.PrintlnDebugStep("Type \"exit\" to exit the console.\n")
}

func (s *server) newTerminal(screen screenIO, commands map[string]commandStruct) error {
	var rErr error

	// Not Initializing with os.Stdin will fail on Windows
	_, rErr = term.MakeRaw(int(os.Stdin.Fd()))
	if rErr != nil {
		return rErr
	}

	// Set Console
	s.console.Term = term.NewTerminal(screen, getPrompt())
	s.console.setConsoleAutoComplete(commands)
	s.console.Output = log.New(s.console.Term, "", 0)

	width, height, tErr := term.GetSize(int(os.Stdout.Fd()))
	if tErr != nil {
		return tErr
	}
	if sErr := s.console.Term.SetSize(width, height); sErr != nil {
		return sErr
	}

	if s.console.FirstRun {
		s.consoleBanner()
		s.console.FirstRun = false
	}

	return nil
}

func (s *server) NewConsole() string {
	var out string

	// Only applies to Windows - Best effort to have a successful raw terminal regardless
	// of the Windows version
	if piErr := s.serverInterpreter.EnableProcessedInputOutput(); piErr != nil {
		s.Logger.Errorf("Failed to enable Processed Input/Output")
		// Sets Console Colors based on if PTY is enabled on the server.
		// If it's not on PTY and fails to set Processed IO, disables colors
		setConsoleColors()
	}
	defer func() {
		if ioErr := s.serverInterpreter.ResetInputOutputModes(); ioErr != nil {
			s.Logger.Errorf("Failed to reset Input/Output modes: %s", ioErr)
		}
	}()

	// Get available Commands
	commands := s.initCommands()

	// Set Console
	var sErr error
	s.console.InitState, sErr = term.GetState(int(os.Stdin.Fd()))
	if sErr != nil {
		s.Logger.Fatalf("Failed to read terminal size: %v", sErr)
	}
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.console.InitState)
	}()
	screen := screenIO{os.Stdin, os.Stdout}
	if ntErr := s.newTerminal(screen, commands); ntErr != nil {
		s.Logger.Fatalf("Failed to initialize terminal: %s", ntErr)
	}

	for consoleInput := true; consoleInput; {
		var fCmd string
		input, err := s.console.Term.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.console.TermPrintf("\rFailed to read input: %s\r\n", err)
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF and kills the terminal.
			// To avoid an unexpected behavior, we will silently create a new terminal
			// and continue
			if ntErr := s.newTerminal(screen, commands); ntErr != nil {
				s.Logger.Fatalf("Failed to recover terminal: %s", ntErr)
			}
			_, _ = s.console.Term.Write([]byte{'\n'})
			continue
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
			// This is meant to be a command to execute locally
			if strings.HasPrefix(fCmd, "!") {
				if len(fCmd) > 1 {
					fullCommand := []string{strings.TrimPrefix(fCmd, "!")}
					fullCommand = append(fullCommand, args[1:]...)
					s.notConsoleCommand(fullCommand)
					continue
				}
			}
			if k, ok := commands[fCmd]; ok {
				k.cmdFunc(args[1:]...)
				s.console.Term.SetPrompt(currentPrompt)
			} else {
				s.console.PrintlnErrorStep("Unknown Command: %q", args)
			}

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
		// If a TAB key is pressed and a text was written
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
	// If a Shell was not set, just return
	if s.serverInterpreter.Shell == "" {
		s.console.PrintlnErrorStep("No Shell set")
		return
	}

	// Else, we'll try to execute the command locally
	s.console.PrintlnWarnStep("Executing local Command: %s", fCmd)
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
	eSession, _ := executeFlags.NewIntFlag("s", "session", 0, "Run command passed as an argument on a session id")
	eAll, _ := executeFlags.NewBoolFlag("a", "all", false, "Run command passed as an argument on all sessions")
	executeFlags.MarkFlagsMutuallyExclusive("s", "a")
	executeFlags.MarkFlagsOneRequired("s", "a")
	executeFlags.SetMinArgs(1)
	executeFlags.Set.Usage = func() {
		executeFlags.PrintUsage(true)
	}

	if pErr := executeFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return
	}

	var sessions []*Session
	if *eSession > 0 {
		session, sessErr := s.getSession(*eSession)
		if sessErr != nil {
			s.console.PrintlnErrorStep("Unknown Session ID %d", *eSession)
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
			s.console.PrintlnInfo("Executing Command on SessionID %d", session.sessionID)
		}

		command := strings.Join(executeFlags.Set.Args(), " ")
		var envVarList []struct{ Key, Value string }

		i := session.newExecInstance(envVarList)

		if err := i.ExecuteCommand(command, s.console.InitState); err != nil {
			s.console.PrintlnErrorStep("%v", err)
		}
		s.console.Println("")
	}
}

func (s *server) sessionsCommand(args ...string) {
	var list bool
	sessionsFlags := sflag.NewFlagPack([]string{sessionsCmd}, sessionsUsage, executeDesc, s.console.Term)
	sInteract, _ := sessionsFlags.NewIntFlag("i", "interactive", 0, "Start Interactive Slider Shell on a Session ID")
	sDisconnect, _ := sessionsFlags.NewIntFlag("d", "disconnect", 0, "Disconnect Session ID")
	sKill, _ := sessionsFlags.NewIntFlag("k", "kill", 0, "Kill Session ID")
	sessionsFlags.MarkFlagsMutuallyExclusive("i", "d", "k")
	sessionsFlags.Set.Usage = func() {
		sessionsFlags.PrintUsage(true)
	}

	if pErr := sessionsFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return
	}

	if len(args) == 0 {
		list = true
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
	sSession, _ := socksFlags.NewIntFlag("s", "session", 0, "Run a Socks5 server over an SSH Channel on a Session ID")
	sPort, _ := socksFlags.NewIntFlag("p", "port", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill, _ := socksFlags.NewIntFlag("k", "kill", 0, "Kill Socks5 Listener and Server on a Session ID")
	sExpose, _ := socksFlags.NewBoolFlag("e", "expose", false, "Expose port to all interfaces")
	socksFlags.MarkFlagsOneRequired("s", "k")
	socksFlags.MarkFlagsMutuallyExclusive("k", "s")
	socksFlags.MarkFlagsMutuallyExclusive("k", "p")
	socksFlags.MarkFlagsMutuallyExclusive("k", "e")
	socksFlags.Set.Usage = func() {
		socksFlags.PrintUsage(true)
	}

	if pErr := socksFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return
	}

	var session *Session
	var sessErr error
	sessionID := *sSession + *sKill
	session, sessErr = s.getSession(sessionID)
	if sessErr != nil {
		s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
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
}

func (s *server) certsCommand(args ...string) {
	certsFlags := sflag.NewFlagPack([]string{certsCmd}, certsUsage, certsDesc, s.console.Term)
	cNew, _ := certsFlags.NewBoolFlag("n", "new", false, "Generate a new Key Pair")
	cRemove, _ := certsFlags.NewIntFlag("r", "remove", 0, "Remove matching index from the Certificate Jar")
	cSSH, _ := certsFlags.NewIntFlag("d", "dump", 0, "Dump CertID SSH keys")
	certsFlags.MarkFlagsMutuallyExclusive("n", "r", "d")
	certsFlags.Set.Usage = func() {
		certsFlags.PrintUsage(true)
	}

	if pErr := certsFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
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
	cCert, _ := connectFlags.NewInt64Flag("c", "cert", 0, "Specify certID for key authentication")
	cDNS, _ := connectFlags.NewStringFlag("d", "dns", "", "Use custom DNS resolver")
	cProto, _ := connectFlags.NewStringFlag("p", "proto", conf.Proto, "Use custom proto")
	connectFlags.SetExactArgs(1)
	connectFlags.Set.Usage = func() {
		connectFlags.PrintUsage(true)
	}

	if pErr := connectFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
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

	go s.newClientConnector(cu, notifier, *cCert, *cDNS, *cProto)

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
	sSession, _ := sshFlags.NewIntFlag("s", "session", 0, "Session ID to establish SSH connection with")
	sPort, _ := sshFlags.NewIntFlag("p", "port", 0, "Local port to forward SSH connection to")
	sKill, _ := sshFlags.NewIntFlag("k", "kill", 0, "Kill SSH port forwarding to a Session ID")
	sExpose, _ := sshFlags.NewBoolFlag("e", "expose", false, "Expose port to all interfaces")
	sshFlags.MarkFlagsOneRequired("s", "k")
	sshFlags.MarkFlagsMutuallyExclusive("k", "s")
	sshFlags.MarkFlagsMutuallyExclusive("k", "p")
	sshFlags.MarkFlagsMutuallyExclusive("k", "e")
	sshFlags.Set.Usage = func() {
		sshFlags.PrintUsage(true)
	}

	if pErr := sshFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return
	}

	var session *Session
	var sessErr error
	sessionID := *sSession + *sKill
	session, sessErr = s.getSession(sessionID)
	if sessErr != nil {
		s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
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
}

func (s *server) shellCommand(args ...string) {
	shellFlags := sflag.NewFlagPack([]string{shellCmd}, shellUsage, shellDesc, s.console.Term)
	sSession, _ := shellFlags.NewIntFlag("s", "session", 0, "Run a Shell server over an SSH Channel on a Session ID")
	sPort, _ := shellFlags.NewIntFlag("p", "port", 0, "Use this port number as local Listener, otherwise randomly selected")
	sKill, _ := shellFlags.NewIntFlag("k", "kill", 0, "Kill Shell Listener and Server on a Session ID")
	sInteractive, _ := shellFlags.NewBoolFlag("i", "interactive", false, "Interactive mode, enters shell directly. Always TLS")
	sTls, _ := shellFlags.NewBoolFlag("t", "tls", false, "Enable TLS for the Shell")
	sExpose, _ := shellFlags.NewBoolFlag("e", "expose", false, "Expose port to all interfaces")
	shellFlags.MarkFlagsOneRequired("s", "k")
	shellFlags.MarkFlagsMutuallyExclusive("k", "s")
	shellFlags.MarkFlagsMutuallyExclusive("k", "p")
	shellFlags.MarkFlagsMutuallyExclusive("k", "i")
	shellFlags.MarkFlagsMutuallyExclusive("k", "t")
	shellFlags.MarkFlagsMutuallyExclusive("k", "e")
	shellFlags.MarkFlagsMutuallyExclusive("i", "e")
	shellFlags.MarkFlagsMutuallyExclusive("i", "t")
	shellFlags.Set.Usage = func() {
		shellFlags.PrintUsage(true)
	}

	if pErr := shellFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return
	}

	var session *Session
	var sessErr error
	sessionID := *sSession + *sKill
	session, sessErr = s.getSession(sessionID)
	if sessErr != nil {
		s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
		return

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

			// When Shell is interactive, we want it to stop once we are done
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

			// If session doesn't support PTY revert Raw Terminal
			if !session.IsPtyOn() {
				s.console.PrintlnWarnStep("Client does not support PTY")
				s.console.PrintlnWarnStep("Pressing CTR^C will interrupt the shell")

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
				}()
			}

			// Clear screen (Windows Command Prompt already does that)
			if string(session.clientInterpreter.System) != "windows" || !session.clientInterpreter.PtyOn {
				s.console.clearScreen()
			}
			// os.StdIn is blocking and will be waiting for any input even if the connection is closed.
			// After pressing a key, io.Copy will fail due to the attempt of copying to a closed writer,
			// which will do the unlocking
			go func() {
				_, _ = io.Copy(os.Stdout, conn)
				s.console.PrintlnWarn("Press ENTER until get back to console")
			}()
			_, _ = io.Copy(conn, os.Stdin)

			return
		} else {
			return
		}
	}

}

func (s *server) portFwdCommand(args ...string) {
	portFwdFlags := sflag.NewFlagPack([]string{portFwdCmd}, portFwdUsage, portFwdDesc, s.console.Term)
	pSession, _ := portFwdFlags.NewIntFlag("s", "session", 0, "Session ID to add or remove Port Forwarding")
	pReverse, _ := portFwdFlags.NewBoolFlag("R", "reverse", false, "Reverse format: <[allowed_remote_addr]:remote_port:[forward_addr]:forward_port>")
	pRemove, _ := portFwdFlags.NewBoolFlag("r", "remove", false, "Remove Port Forwarding form port passed as argument")
	portFwdFlags.MarkFlagsRequireArgs("R", 1)
	portFwdFlags.MarkFlagsRequireArgs("r", 1)
	/*
		pLocal, _ := portFwdFlags.NewBoolFlag("l", "local", false, "Local Port Forwarding <[local_addr]:local_port:[remote_addr]:remote_port>")
		portFwdFlags.MarkFlagsRequireArgs("l", 1)
		portFwdFlags.MarkFlagsMutuallyExclusive("l", "r")

	*/
	portFwdFlags.Set.Usage = func() {
		portFwdFlags.PrintUsage(true)
	}

	if pErr := portFwdFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return
	}

	var session *Session
	if *pSession > 0 {
		var sErr error
		session, sErr = s.getSession(*pSession)
		if sErr != nil {
			s.console.PrintlnErrorStep("Unknown Session ID %d", *pSession)
			return
		}
	}

	if len(portFwdFlags.Set.Args()) == 0 {
		// List of the Port Forwarding
		tw := new(tabwriter.Writer)
		tw.Init(s.console.Term, 0, 4, 2, ' ', 0)

		totalGlobalTcpIpFwd := 0
		sessionList := slices.Collect(maps.Values(s.sessionTrack.Sessions))

		for _, sItem := range sessionList {
			reverseMappings := sItem.SSHInstance.GetReverseMappings()
			totalSessionTcpIpFwd := len(reverseMappings)
			totalGlobalTcpIpFwd += totalSessionTcpIpFwd
			if totalSessionTcpIpFwd == 0 {
				continue
			}
			_, _ = fmt.Fprintln(tw)
			_, _ = fmt.Fprintf(tw, "\tSession ID\tForward Address\tLocal Port\tRemote Address\tRemote Port\n")
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
			s.console.PrintlnDebugStep("Active Port Forwards: %d\n", totalSessionTcpIpFwd)
			_ = tw.Flush()
		}

		if totalGlobalTcpIpFwd == 0 {
			s.console.PrintlnDebugStep("Active Port Forwards: %d\n", totalGlobalTcpIpFwd)
		}
		return
	}

	if *pReverse {
		if session == nil {
			s.console.PrintlnErrorStep("Session ID not specified")
			return
		}

		if *pRemove {
			port, pErr := parsePort(portFwdFlags.Set.Args()[0])
			if pErr != nil {
				s.console.PrintlnErrorStep("Error: %v", pErr)
				return
			}
			sErr := session.SSHInstance.CancelMsgReverseFwd(port)
			if sErr != nil {
				s.console.PrintlnErrorStep("Failed to remove: %v", sErr)
				return
			}
			s.console.PrintlnOkStep("Remote Port forwarding (port %d) removed successfully", port)
			return
		}

		// Create Reverse Port Forwarding
		fwdItem := portFwdFlags.Set.Args()[0]
		msg, pErr := parseForwarding(fwdItem)
		if pErr != nil {
			s.console.PrintlnErrorStep("Failed to parse Port Forwarding %s: %s", fwdItem, pErr)
			return
		}
		s.console.PrintlnDebugStep("Creating Port Forwarding %s:%d->%s:%d", msg.SrcHost, msg.SrcPort, msg.DstHost, msg.DstPort)
		go session.SSHInstance.TcpIpForwardFromMsg(*msg)
		var sErr error
		port := int(msg.SrcPort)
		shellTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)
		for range shellTicker.C {
			if !time.Now().Before(timeout) {
				s.console.PrintlnErrorStep("Port forward request timed out")
				return
			}
			_, sErr = session.SSHInstance.GetReversePortMapping(port)
			if port == 0 || sErr != nil {
				fmt.Printf(".")
				continue
			} else {
				s.console.PrintlnOkStep("Forwarding established on remote port: %d", port)
				break
			}
		}
		return
	}

}

func parsePort(input string) (int, error) {
	remotePort, iErr := strconv.Atoi(input)
	if iErr != nil || remotePort < 1 || remotePort > 65535 {
		return 0, fmt.Errorf("invalid port: %s", input)
	}
	return remotePort, nil
}

func parseForwarding(input string) (*types.CustomTcpIpChannelMsg, error) {
	var remoteAddr, localAddr string
	var remotePort, localPort int
	msg := &types.CustomTcpIpChannelMsg{}

	portFwd := strings.Split(input, ":")

	switch len(portFwd) {
	case 3:
		remoteAddr = "0.0.0.0"
		var iErr error
		remotePort, iErr = parsePort(portFwd[0])
		if iErr != nil {
			return msg, iErr
		}
		localAddr = portFwd[1]
		if localAddr == "" {
			localAddr = "localhost"
		}
		localPort, iErr = parsePort(portFwd[2])
		if iErr != nil {
			return msg, iErr
		}
	case 4:
		remoteAddr = portFwd[0]
		var iErr error
		remotePort, iErr = parsePort(portFwd[1])
		if iErr != nil {
			return msg, iErr
		}
		localAddr = portFwd[2]
		if localAddr == "" {
			localAddr = "localhost"
		}
		localPort, iErr = parsePort(portFwd[3])
		if iErr != nil {
			return msg, iErr
		}

	default:
		return msg, fmt.Errorf("invalid Port Forwarding format: %s", input)
	}

	msg.IsSshConn = false
	msg.TcpIpChannelMsg = &types.TcpIpChannelMsg{
		DstHost: localAddr,
		DstPort: uint32(localPort),
		SrcHost: remoteAddr,
		SrcPort: uint32(remotePort),
	}

	return msg, nil
}
