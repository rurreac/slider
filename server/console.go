package server

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slider/pkg/colors"
	"slider/pkg/conf"
	"slider/pkg/sio"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

type Console struct {
	Term      *term.Terminal
	InitState *term.State
	Output    *log.Logger
}

func (s *server) NewConsole() string {
	var out string

	// Set Screen
	s.console.InitState, _ = term.MakeRaw(int(os.Stdin.Fd()))
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.console.InitState)
	}()

	screen := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	// Set Console
	s.console.Term = term.NewTerminal(screen, "")
	s.console.Output = log.New(s.console.Term, "", 0)

	// Set Console
	if width, height, tErr := term.GetSize(int(os.Stdin.Fd())); tErr == nil {
		// Disregard the error if fails setting Console size
		_ = s.console.Term.SetSize(width, height)
	}
	s.console.PrintlnWarn(
		"\r\nPress CTRL^C again or Type \"bg\" to background the console," +
			"\r\nType \"exit\" to terminate the server.\r\n",
	)
	s.console.Term.SetPrompt(
		"\rSlider" +
			string(colors.Console.System) +
			" > " +
			string(colors.Reset),
	)

	for consoleInput := true; consoleInput; {
		var fCmd string
		input, err := s.console.Term.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.console.Printf("\rFailed to read input: %s\r\n", err)
				break
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF
			// We will background gracefully when this happens
			s.console.Println("")
			return "bg"
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)

		if len(args) > 0 {
			fCmd = args[0]
		}

		commands := s.initCommands()

		switch fCmd {
		case exitCmd, bgCmd:
			consoleInput = false
			out = fCmd
		case helpCmd:
			s.printConsoleHelp()
		case "":
			continue
		default:
			if k, ok := commands[fCmd]; ok {
				k.cmdFunc(args[1:]...)
			} else {
				s.notConsoleCommand(args)
			}
		}
	}

	return out
}

func (s *server) notConsoleCommand(fCmd []string) {
	s.console.PrintWarnSelect("Console does not recognize Command: ", fCmd...)

	// If a Shell was not set just return
	if s.serverInterpreter.Shell == "" {
		return
	}

	// Else, we'll try to execute the command locally
	s.console.PrintlnWarn("Will run an OS command locally instead...")
	fCmd = append(s.serverInterpreter.CmdArgs, strings.Join(fCmd, " "))

	cmd := exec.Command(s.serverInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Stdout = s.console.Term
	cmd.Stderr = s.console.Term
	if err := cmd.Run(); err != nil {
		s.console.PrintlnErrorStep("%v", err)
	}

}

func (s *server) executeCommand(args ...string) {
	executeFlags := flag.NewFlagSet(executeCmd, flag.ContinueOnError)
	executeFlags.SetOutput(s.console.Term)
	eSession := executeFlags.Int("s", 0, "Runs given command on a Session ID")
	eAll := executeFlags.Bool("a", false, "Runs given command on every Session")
	executeFlags.Usage = func() {
		s.console.PrintCommandUsage(executeFlags, executeDesc+executeUsage)
	}

	if pErr := executeFlags.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 || (*eAll && *eSession > 0) || (!*eAll && *eSession == 0) {
		executeFlags.Usage()
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
		if _, _, err := session.sendRequest(
			"session-exec",
			true,
			[]byte(strings.Join(executeFlags.Args(), " ")),
		); err != nil {
			s.console.PrintlnErrorStep("%v", err)
			continue
		}
		if sErr := session.sessionExecute(s.console.InitState); sErr != nil {
			s.console.PrintlnErrorStep("%v", sErr)
			continue
		}
	}
}

func (s *server) sessionsCommand(args ...string) {
	sessionsFlags := flag.NewFlagSet(sessionsCmd, flag.ContinueOnError)
	sessionsFlags.SetOutput(s.console.Term)

	sList := sessionsFlags.Bool("l", false, "Lists Server Sessions")
	sInteract := sessionsFlags.Int("i", 0, "Starts Interactive Shell on a Session ID")
	sKill := sessionsFlags.Int("k", 0, "Kills Session ID")
	sessionsFlags.Usage = func() {
		s.console.PrintCommandUsage(sessionsFlags, sessionsDesc+sessionsUsage)
	}

	if pErr := sessionsFlags.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 || sessionsFlags.NArg() > 1 || (*sList && ((*sInteract + *sKill) > 0)) {
		sessionsFlags.Usage()
		return
	}

	var err error

	if *sList {
		if len(s.sessionTrack.Sessions) > 0 {
			var keys []int
			for i := range s.sessionTrack.Sessions {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			tw := new(tabwriter.Writer)
			tw.Init(s.console.Term, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintf(tw, "\n\tID\tSystem\tUser\tHost\tIO\tConnection\tSocks\tFingerprint\t\n")

			for _, i := range keys {
				session := s.sessionTrack.Sessions[int64(i)]
				socksPort := fmt.Sprintf("%d", session.SocksInstance.Port)
				if socksPort == "0" {
					socksPort = "--"
				}

				if session.ClientInterpreter != nil {
					fingerprint := session.fingerprint
					if fingerprint == "" {
						fingerprint = "--"
					}
					var inOut = "<-"
					if session.IsListener {
						inOut = "->"
					}
					_, _ = fmt.Fprintf(tw, "\t%d\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
						session.sessionID,
						session.ClientInterpreter.Arch,
						session.ClientInterpreter.System,
						session.ClientInterpreter.User,
						session.ClientInterpreter.Hostname,
						inOut,
						session.wsConn.RemoteAddr().String(),
						socksPort,
						fingerprint,
					)

				}
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		s.console.Printf("Active sessions: %d\n", s.sessionTrack.SessionActive)
		return
	}

	if *sInteract > 0 {
		session, sessErr := s.getSession(*sInteract)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sInteract)
			return
		}
		if _, _, err = session.sendRequest(
			"session-shell",
			true,
			nil,
		); err != nil {
			s.console.Printf("%s", err)
			return
		}
		session.sessionInteractive(s.console.InitState, s.serverInterpreter.WinChangeCall)
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sKill)
			return
		}
		if _, _, err = session.sendRequest(
			"disconnect",
			true,
			nil,
		); err != nil {
			s.console.Printf("%s", err)
			return
		}
		s.console.PrintlnOkStep("SessionID %d terminated gracefully", *sKill)

		return
	}
}

func (s *server) socksCommand(args ...string) {
	socksFlags := flag.NewFlagSet(socksCmd, flag.ContinueOnError)
	socksFlags.SetOutput(s.console.Term)
	sSession := socksFlags.Int("s", 0, "Runs a Socks5 server over an SSH Channel on a Session ID")
	sPort := socksFlags.Int("p", 0, "Uses this port number as local Listener, otherwise randomly selected")
	sKill := socksFlags.Int("k", 0, "Kills Socks5 Listener and Server on a Session ID")
	socksFlags.Usage = func() {
		s.console.PrintCommandUsage(socksFlags, socksDesc+socksUsage)
	}

	if pErr := socksFlags.Parse(args); pErr != nil {
		return
	}

	var session *Session
	var sessErr error
	if (*sSession == 0 && *sKill == 0) || (*sSession > 0 && *sKill > 0) {
		socksFlags.Usage()
		return
	} else {
		sessionID := *sSession + *sKill
		session, sessErr = s.getSession(sessionID)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
			return
		}
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
		s.console.PrintlnDebugStep("No Socks Server found running on Session ID %d", *sKill)
		return
	}

	if *sSession > 0 {
		if session.SocksInstance.IsEnabled() {
			s.console.PrintlnErrorStep("Socks Endpoint is already running on Port: %d", session.SocksInstance.Port)
			return
		}
		s.console.PrintlnDebugStep("Enabling Socks5 Endpoint in the background")

		go session.socksEnable(*sPort)

		// Give some time to check
		socksTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)
		for {
			select {
			case <-socksTicker.C:
				if time.Now().Before(timeout) {
					port, _ := session.SocksInstance.GetEndpointPort()
					if port == 0 {
						continue
					}
					s.console.PrintlnOkStep("Socks Endpoint running on Port: %d", port)
					return
				}
				s.console.PrintlnErrorStep("Socks Endpoint doesn't appear to be running")
				return
			}
		}
	}
	socksFlags.Usage()
}

func (s *server) uploadCommand(args ...string) {
	uploadFlags := flag.NewFlagSet(uploadCmd, flag.ContinueOnError)
	uploadFlags.SetOutput(s.console.Term)
	uSession := uploadFlags.Int("s", 0, "Uploads file to selected Session ID")
	uploadFlags.Usage = func() {
		s.console.PrintCommandUsage(uploadFlags, uploadDesc+uploadUsage)
	}

	if pErr := uploadFlags.Parse(args); pErr != nil {
		return
	}

	if len(uploadFlags.Args()) > 2 || len(uploadFlags.Args()) < 1 {
		uploadFlags.Usage()
		return
	}

	if *uSession > 0 {
		session, sessErr := s.getSession(*uSession)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *uSession)
			return
		}

		src := uploadFlags.Args()[0]
		dst := filepath.Base(src)
		if len(uploadFlags.Args()) == 2 {
			dst = uploadFlags.Args()[1]
		}

		for statusChan := range session.uploadFile(src, dst) {
			if statusChan.Success {
				s.console.PrintlnOkStep("Uploaded \"%s\" -> \"%s\" (sha256:%s)",
					src,
					statusChan.FileName,
					statusChan.CheckSum,
				)
			} else {
				s.console.PrintlnErrorStep("Failed to Upload \"%s\": %v", src, statusChan.Err)
			}
		}
	}
}

func (s *server) downloadCommand(args ...string) {
	downloadFlags := flag.NewFlagSet(downloadCmd, flag.ContinueOnError)
	downloadFlags.SetOutput(s.console.Term)
	dSession := downloadFlags.Int("s", 0, "Downloads file from a given a Session ID")
	dFile := downloadFlags.String("f", "", "Receives a file list with items to download")
	downloadFlags.Usage = func() {
		s.console.PrintCommandUsage(downloadFlags, downloadDesc+downloadUsage)
	}

	if pErr := downloadFlags.Parse(args); pErr != nil {
		return
	}

	if *dSession == 0 {
		downloadFlags.Usage()
		return
	}

	if *dSession > 0 {
		session, sessErr := s.getSession(*dSession)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *dSession)
			return
		}

		if *dFile == "" && downloadFlags.NFlag() >= 2 {
			s.console.PrintlnDebugStep("Need to provide a filelist")
			return
		} else if *dFile != "" {
			s.console.PrintlnDebugStep("Output Dir: \"%s\"", sio.GetSliderHome())

			for statusChan := range session.downloadFileBatch(*dFile) {
				if statusChan.Success {
					s.console.PrintlnOkStep("Downloaded \"%s\" (sha256:%s)",
						statusChan.FileName,
						statusChan.CheckSum,
					)
				} else {
					s.console.PrintlnErrorStep("Failed to Download \"%v\"", statusChan.Err)
				}
			}
			return
		}

		if len(downloadFlags.Args()) > 2 || len(downloadFlags.Args()) < 1 {
			s.console.PrintlnDebugStep("Incorrect number of arguments")
			return
		}

		src := downloadFlags.Args()[0]
		dst := filepath.Base(src)
		if len(downloadFlags.Args()) == 2 {
			dst = downloadFlags.Args()[1]
		}

		for statusChan := range session.downloadFile(src, dst) {
			if statusChan.Success {
				s.console.PrintlnOkStep("Downloaded \"%s\" -> \"%s\" (sha256:%s)",
					src,
					statusChan.FileName,
					statusChan.CheckSum,
				)
			} else {
				s.console.PrintlnErrorStep("Failed to Download \"%s\": %v", src, statusChan.Err)
			}
		}
	}
}

func (s *server) certsCommand(args ...string) {
	certsFlags := flag.NewFlagSet(certsCmd, flag.ContinueOnError)
	certsFlags.SetOutput(s.console.Term)
	cNew := certsFlags.Bool("n", false, "Generate a new Key Pair")
	cList := certsFlags.Bool("l", false, "List all available Key Pairs")
	cRemove := certsFlags.Int("r", 0, "Remove matching index from the Certificate Jar")
	certsFlags.Usage = func() {
		s.console.PrintCommandUsage(certsFlags, certsDesc+certsUsage)
	}
	if err := certsFlags.Parse(args); err != nil {
		return
	}

	if !*cList && !*cNew && *cRemove == 0 {
		certsFlags.Usage()
	}

	if *cRemove > 0 {
		if err := s.dropCertItem(int64(*cRemove)); err != nil {
			s.console.PrintlnErrorStep("%s", err)
			return
		}
		s.console.PrintlnOkStep("Certificate successfully removed")
		return
	}

	if *cList {
		if len(s.certTrack.Certs) > 0 {
			var keys []int
			for i := range s.certTrack.Certs {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			twl := new(tabwriter.Writer)
			twl.Init(s.console.Term, 0, 4, 2, ' ', 0)

			for _, k := range keys {
				_, _ = fmt.Fprintln(twl)
				_, _ = fmt.Fprintf(twl, "\tCertID %d\n\t%s\n",
					k,
					strings.Repeat("-", 11),
				)
				_, _ = fmt.Fprintf(twl, "\tPrivate Key:\t%s\t\n", s.certTrack.Certs[int64(k)].ExtractKeyFromPem())
				_, _ = fmt.Fprintf(twl, "\tFingerprint:\t%s\t\n", s.certTrack.Certs[int64(k)].FingerPrint)
				_, _ = fmt.Fprintf(twl, "\tUsed by Session:\t%d\t\n", s.getSessionByCert(s.certTrack.Certs[int64(k)].FingerPrint))
			}
			_, _ = fmt.Fprintln(twl)
			_ = twl.Flush()
		}
		s.console.Printf("Certificates in Jar: %d\n", s.certTrack.CertActive)
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
		_, _ = fmt.Fprintf(twn, "\tPrivate Key:\t%s\t\n", keypair.ExtractKeyFromPem())
		_, _ = fmt.Fprintf(twn, "\tFingerprint:\t%s\t\n", keypair.FingerPrint)
		_, _ = fmt.Fprintln(twn)
		_ = twn.Flush()

		return
	}
}

func (s *server) connectCommand(args ...string) {
	connectFlags := flag.NewFlagSet(connectCmd, flag.ContinueOnError)
	connectFlags.Usage = func() {
		s.console.PrintCommandUsage(connectFlags, connectDesc+connectUsage)
	}
	if err := connectFlags.Parse(args); err != nil {
		return
	}
	if len(connectFlags.Args()) == 0 || len(connectFlags.Args()) > 1 {
		connectFlags.Usage()
		return
	}
	clientAddr, rErr := net.ResolveTCPAddr("tcp", connectFlags.Args()[0])
	if rErr != nil {
		s.console.PrintlnErrorStep("Argument \"%s\" is not a valid address", connectFlags.Args()[0])
		return
	}
	var ip = clientAddr.IP.String()
	if clientAddr.IP == nil {
		ip = "127.0.0.1"
	}
	s.console.PrintlnDebugStep("Establishing Connection to %s:%d (Timeout: %s)", ip, clientAddr.Port, conf.Timeout)

	notifier := make(chan bool, 1)
	timeout := time.Now().Add(conf.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)

	go s.newClientConnector(clientAddr, notifier)

	for {
		select {
		case connected := <-notifier:
			if connected {
				s.console.PrintlnOkStep("Successfully connected to Client %s:%d", ip, clientAddr.Port)
				close(notifier)
				return
			} else {
				s.console.PrintlnErrorStep("Failed to connect to Client %s:%d", ip, clientAddr.Port)
				close(notifier)
				return
			}
		case t := <-ticker.C:
			if t.After(timeout) {
				s.console.PrintlnErrorStep("Timed out connecting to Client %s:%d", ip, clientAddr.Port)
				close(notifier)
				return
			}
		}
	}
}
