package server

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slider/pkg/interpreter"
	"slider/pkg/sio"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"
)

func (s *server) NewConsole() string {
	var out string

	// Set Interpreter
	if s.ServerInterpreter == nil {
		i, iErr := interpreter.NewInterpreter()
		if iErr != nil {
			s.Errorf("%s", iErr)
		}
		s.setInterpreter(i)
	}

	// Set Screen
	s.consoleState, _ = term.MakeRaw(int(os.Stdin.Fd()))
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.consoleState)
	}()

	screen := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	// Set Console
	s.console = term.NewTerminal(screen, "")
	if width, height, tErr := term.GetSize(int(os.Stdin.Fd())); tErr == nil {
		// Disregard the error if fails setting Console size
		_ = s.console.SetSize(width, height)
	}
	fmt.Printf(
		"\n\rPress CTRL^C again or Type \"bg\" to background the console," +
			"\n\rType \"exit\" to terminate the server.\n\n\r",
	)
	s.console.SetPrompt(
		"\rSlider" +
			string(s.console.Escape.Cyan) +
			">" +
			string(s.console.Escape.Reset) + " ",
	)

	for consoleInput := true; consoleInput; {
		var fCmd string
		input, err := s.console.ReadLine()
		if err != nil {
			if err != io.EOF {
				_, _ = fmt.Fprintf(s.console, "\rFailed to read input: %s\n\r", err)
				break
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF
			// We will background gracefully when this happens
			_, _ = fmt.Fprintf(s.console, "\r\n")
			return "bg"
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)

		if len(args) > 0 {
			fCmd = args[0]
		}

		switch fCmd {
		case sessionsCmd:
			s.sessionsCommand(args[1:]...)
		case executeCmd:
			s.executeCommand(args[1:]...)
		case exitCmd, bgCmd:
			consoleInput = false
			out = fCmd
		case socksCmd:
			s.socksCommand(args[1:]...)
		case uploadCmd:
			s.uploadCommand(args[1:]...)
		case downloadCmd:
			s.downloadCommand(args[1:]...)
		case helpCmd:
			printConsoleHelp(s.console)
		case "":
			continue
		default:
			s.notConsoleCommand(args)
		}
	}

	return out
}

func (s *server) setInterpreter(i *interpreter.Interpreter) {
	s.ServerInterpreter = i
}

func (s *server) notConsoleCommand(fCmd []string) {
	_, _ = fmt.Fprintf(s.console,
		"\r%sConsole does not recognize Command: %s%s\n",
		string(s.console.Escape.Yellow),
		string(s.console.Escape.Reset),
		fCmd,
	)

	// If a Shell was not set just return
	if s.ServerInterpreter.Shell == "" {
		return
	}

	// Else, we'll try to execute the command locally
	fCmd = append(s.ServerInterpreter.CmdArgs, strings.Join(fCmd, " "))

	_, _ = fmt.Fprintf(s.console,
		"\r%sWill run an OS command locally instead...%s\n\r",
		string(s.console.Escape.Yellow),
		string(s.console.Escape.Reset),
	)

	cmd := exec.Command(s.ServerInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Stdout = s.console
	cmd.Stderr = s.console
	if err := cmd.Run(); err != nil {
		_, _ = fmt.Fprintf(s.console, "\r%s\n\r", err)
	}

}

func (s *server) executeCommand(args ...string) {
	executeFlags := flag.NewFlagSet("execute", flag.ContinueOnError)
	executeFlags.SetOutput(s.console)
	eSession := executeFlags.Int("s", 0, "Runs given command on a Session ID")
	eAll := executeFlags.Bool("a", false, "Runs given command on every Session")

	executeFlags.Usage = func() {
		_, _ = fmt.Fprintf(s.console, executeShort+executeLong)
		executeFlags.PrintDefaults()
		_, _ = fmt.Fprintln(s.console)
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
			fmt.Printf("\r%s\n\n\r", sessErr)
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
			fmt.Printf(
				"\r%sExecuting Command on %sSessionID %d%s.%s\r\n",
				s.console.Escape.Yellow,
				s.console.Escape.Reset,
				session.sessionID,
				s.console.Escape.Yellow,
				s.console.Escape.Reset,
			)
		}
		if _, _, err := session.sendRequest(
			"session-exec",
			true,
			[]byte(strings.Join(executeFlags.Args(), " ")),
		); err != nil {
			fmt.Printf("\r%s\n\n\r", err)
			continue
		}
		if sErr := session.sessionExecute(s.consoleState); sErr != nil {
			fmt.Printf("\r%s\n\n\r", sErr)
			continue
		}
	}
}

func (s *server) sessionsCommand(args ...string) {
	sessionsFlags := flag.NewFlagSet("sessions", flag.ContinueOnError)
	sessionsFlags.SetOutput(s.console)

	sList := sessionsFlags.Bool("l", false, "Lists Server Sessions")
	sInteract := sessionsFlags.Int("i", 0, "Starts Interactive Shell on a Session ID")
	sKill := sessionsFlags.Int("k", 0, "Kills Session ID")
	sessionsFlags.Usage = func() {
		_, _ = fmt.Fprintf(s.console, sessionsShort+sessionsLong)
		sessionsFlags.PrintDefaults()
		_, _ = fmt.Fprintln(s.console)
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
			tw := new(tabwriter.Writer)
			tw.Init(s.console, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintf(tw, "\n\tID\tSystem\tUser\tHost\tConnection\tSocks\t\n")

			for sID, session := range s.sessionTrack.Sessions {
				socksPort := fmt.Sprintf("%d", session.SocksInstance.Port)
				if socksPort == "0" {
					socksPort = "--"
				}
				_, _ = fmt.Fprintf(tw, "\t%d\t%s/%s\t%s\t%s\t%s\t%s\t\n",
					sID,
					session.ClientInterpreter.Arch,
					session.ClientInterpreter.System,
					session.ClientInterpreter.User,
					session.ClientInterpreter.Hostname,
					session.shellWsConn.RemoteAddr().String(),
					socksPort)
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		_, _ = fmt.Fprintf(s.console, "\rActive sessions: %d\n\r\n", s.sessionTrack.SessionActive)
		return
	}

	if *sInteract > 0 {
		session, sessErr := s.getSession(*sInteract)
		if sessErr != nil {
			_, _ = fmt.Fprintf(s.console, "\r%s\n\n\r", sessErr)
			return
		}
		if _, _, err = session.sendRequest(
			"session-shell",
			true,
			nil,
		); err != nil {
			_, _ = fmt.Fprintf(s.console, "\r%s\n\n\r", err)
			return
		}
		session.sessionInteractive(s.consoleState, s.console, s.ServerInterpreter.WinChangeCall)
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			_, _ = fmt.Fprintf(s.console, "\r%s\n\n\r", sessErr)
			return
		}
		if _, _, err = session.sendRequest(
			"disconnect",
			true,
			nil,
		); err != nil {
			_, _ = fmt.Fprintf(s.console, "\r%s\n\r", err)
			return
		}
		_, _ = fmt.Fprintf(s.console, "\r[+] SessionID %d terminated gracefully\r\n\n", *sKill)
		return
	}
}

func (s *server) socksCommand(args ...string) {
	socksFlags := flag.NewFlagSet("socks", flag.ContinueOnError)
	socksFlags.SetOutput(s.console)
	sSession := socksFlags.Int("s", 0, "Runs a Socks5 server over an SSH Channel on a Session ID")
	sPort := socksFlags.Int("p", 0, "Uses this port number as local Listener, otherwise randomly selected")
	sKill := socksFlags.Int("k", 0, "Kills Socks5 Listener and Server on a Session ID")
	socksFlags.Usage = func() {
		_, _ = fmt.Fprintf(s.console, socksShort+socksLong)
		socksFlags.PrintDefaults()
		_, _ = fmt.Fprintln(s.console)
	}

	if pErr := socksFlags.Parse(args); pErr != nil {
		return
	}

	if *sSession == 0 && *sKill == 0 {
		socksFlags.Usage()
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			_, _ = fmt.Fprintf(s.console, "\r[*] Unknown Session ID %d\r\n\n", *sKill)
			return
		}
		if session.SocksInstance.IsEnabled() {
			if err := session.SocksInstance.Stop(); err != nil {
				_, _ = fmt.Fprintf(s.console, "\r[!] %s\n\r", err)
				return
			}
			_, _ = fmt.Fprintf(s.console, "\r[+] Socks Endpoint gracefully stopped\n\n")
			return
		}
		_, _ = fmt.Fprintf(s.console, "\r[*] No Socks Server found running on Session ID %d\r\n\n", *sKill)
		return
	}

	if *sSession > 0 {
		session, sessErr := s.getSession(*sSession)
		if sessErr != nil {
			_, _ = fmt.Fprintf(s.console, "\n[*] Unknown Session ID %d\n\n", *sSession)
			return
		}
		_, _ = fmt.Fprintf(s.console, "\r[*] Enabling Socks5 Endpoint in the background\r\n")

		go session.socksEnable(*sPort)

		// TODO: this should be done with pipelines
		// Give some time to check
		timeout := time.Now().Add(5 * time.Second)
		for time.Now().Before(timeout) {
			port, _ := session.SocksInstance.GetEndpointPort()
			if port == 0 {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			_, _ = fmt.Fprintf(s.console, "\r[+] Socks Endpoint running on port \"%d\"\r\n", port)
			return
		}
		_, _ = fmt.Fprintf(s.console, "\r[!] Socks Endpoint doesn't appear to be running\r\n")
		return
	}
	socksFlags.Usage()
}

func (s *server) uploadCommand(args ...string) {
	uploadFlags := flag.NewFlagSet("upload", flag.ContinueOnError)
	uploadFlags.SetOutput(s.console)
	uSession := uploadFlags.Int("s", 0, "Uploads file to selected Session ID")
	uploadFlags.Usage = func() {
		_, _ = fmt.Fprintf(s.console, uploadShort+uploadLong)
		uploadFlags.PrintDefaults()
		_, _ = fmt.Fprintln(s.console)
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
			_, _ = fmt.Fprintf(s.console, "\n[*] Unknown Session ID %d\n\n", *uSession)
			return
		}

		src := uploadFlags.Args()[0]
		dst := filepath.Base(src)
		if len(uploadFlags.Args()) == 2 {
			dst = uploadFlags.Args()[1]
		}

		for statusChan := range session.uploadFile(src, dst) {
			if statusChan.Success {
				_, _ = fmt.Fprintf(s.console,
					"\r[+] Uploaded \"%s\" -> \"%s\" (sha256:%s)\r\n",
					src,
					statusChan.FileName,
					statusChan.CheckSum,
				)
			} else {
				_, _ = fmt.Fprintf(s.console, "\r[!] Failed to Upload \"%s\": %s\r\n", src, statusChan.Err)
			}
		}
	}
}

func (s *server) downloadCommand(args ...string) {
	downloadFlags := flag.NewFlagSet("download", flag.ContinueOnError)
	downloadFlags.SetOutput(s.console)
	dSession := downloadFlags.Int("s", 0, "Downloads file from a given a Session ID")
	dFile := downloadFlags.String("f", "", "Receives a filelist with items to download")
	downloadFlags.Usage = func() {
		_, _ = fmt.Fprintf(s.console, downloadShort+downloadLong)
		downloadFlags.PrintDefaults()
		_, _ = fmt.Fprintln(s.console)
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
			_, _ = fmt.Fprintf(s.console, "\n[*] Unknown Session ID %d\n\n", *dSession)
			return
		}

		if *dFile == "" && downloadFlags.NFlag() >= 2 {
			_, _ = fmt.Fprintf(s.console, "\r[*] Need to provide a list file\n\r")
			return
		} else if *dFile != "" {
			_, _ = fmt.Fprintf(s.console, "\rOutput Dir: \"%s\"", sio.GetOutputDir())
			for statusChan := range session.downloadFileBatch(*dFile) {
				if statusChan.Success {
					_, _ = fmt.Fprintf(s.console,
						"\r[+] Downloaded \"%s\" (sha256:%s)\r\n",
						statusChan.FileName,
						statusChan.CheckSum,
					)
				} else {
					_, _ = fmt.Fprintf(s.console, "\r[!] Failed to Download \"%s\"\r\n", statusChan.Err)
				}
			}
			return
		}

		if len(downloadFlags.Args()) > 2 || len(downloadFlags.Args()) < 1 {
			_, _ = fmt.Fprintf(s.console, "\r[*] Incorrect number of arguments\r\n")
			return
		}

		src := downloadFlags.Args()[0]
		dst := filepath.Base(src)
		if len(downloadFlags.Args()) == 2 {
			dst = downloadFlags.Args()[1]
		}

		for statusChan := range session.downloadFile(src, dst) {
			if statusChan.Success {
				_, _ = fmt.Fprintf(s.console,
					"\r[+] Downloaded \"%s\" -> \"%s\" (sha256:%s)\r\n",
					src,
					statusChan.FileName,
					statusChan.CheckSum,
				)
			} else {
				_, _ = fmt.Fprintf(s.console, "\r[!] Failed to Download \"%s\": %s\r\n", src, statusChan.Err)
			}
		}
	}
}
