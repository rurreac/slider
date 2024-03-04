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
				fmt.Printf("\rFailed to read input: %s\n\r", err)
				break
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF
			// We will background gracefully when this happens
			fmt.Printf("\r\n")
			return "bg"
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)

		if len(args) > 0 {
			fCmd = args[0]
		}

		switch fCmd {
		case "sessions":
			s.cmdSessions(args[1:]...)
		case "execute":
			s.cmdExecute(args[1:]...)
		case "exit", "bg":
			consoleInput = false
			out = fCmd
		case "socks":
			s.cmdSocks(args[1:]...)
		case "upload":
			s.cmdUpload(args[1:]...)
		case "download":
			s.cmdDownload(args[1:]...)
		case "help":
			s.cmdSessions()
			s.cmdExecute()
			s.cmdSocks()
			s.cmdUpload()
			s.cmdDownload()
		case "":
			continue
		default:
			s.notConsoleCmd(args)
		}
	}

	return out
}

func (s *server) setInterpreter(i *interpreter.Interpreter) {
	s.ServerInterpreter = i
}

func (s *server) notConsoleCmd(fCmd []string) {
	_, _ = fmt.Printf(
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

	_, _ = fmt.Printf(
		"\r%sWill run an OS command locally instead...%s\n\r",
		string(s.console.Escape.Yellow),
		string(s.console.Escape.Reset),
	)

	cmd := exec.Command(s.ServerInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Stdout = s.console
	cmd.Stderr = s.console
	if err := cmd.Run(); err != nil {
		fmt.Printf("\r%s\n\r", err)
	}

}

func (s *server) cmdExecute(args ...string) {
	executeCmd := flag.NewFlagSet("execute", flag.ContinueOnError)
	eSession := executeCmd.Int("s", 0, "Run given command on Session ID")
	eAll := executeCmd.Bool("a", false, "Run given command on every Session")

	executeCmd.SetOutput(s.console)

	if pErr := executeCmd.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 || (*eAll && *eSession > 0) || (!*eAll && *eSession == 0) {
		executeCmd.Usage()
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
			[]byte(strings.Join(executeCmd.Args(), " ")),
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

func (s *server) cmdSessions(args ...string) {
	sessionsCmd := flag.NewFlagSet("sessions", flag.ContinueOnError)

	sList := sessionsCmd.Bool("l", false, "List Server Sessions")
	sInteract := sessionsCmd.Int("i", 0, "Start Interactive Shell on Session ID")
	sKill := sessionsCmd.Int("k", 0, "Kill Session ID")

	sessionsCmd.SetOutput(s.console)

	if pErr := sessionsCmd.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 || sessionsCmd.NArg() > 1 || (*sList && ((*sInteract + *sKill) > 0)) {
		sessionsCmd.Usage()
		return
	}

	var err error

	if *sList {
		if len(s.sessionTrack.Sessions) > 0 {
			tw := new(tabwriter.Writer)
			tw.Init(s.console, 0, 4, 2, ' ', tabwriter.AlignRight)
			_, _ = fmt.Fprintln(tw, "\n\tID\tSystem\tUser\tHost\tConnection\tSocks\t")

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
		_, _ = fmt.Printf("\rActive sessions: %d\n\n\r", s.sessionTrack.SessionActive)
		return
	}

	if *sInteract > 0 {
		session, sessErr := s.getSession(*sInteract)
		if sessErr != nil {
			_, _ = fmt.Printf("\r%s\n\n\r", sessErr)
			return
		}
		if _, _, err = session.sendRequest(
			"session-shell",
			true,
			nil,
		); err != nil {
			_, _ = fmt.Printf("\r%s\n\n\r", err)
			return
		}
		session.sessionInteractive(s.consoleState, s.console, s.ServerInterpreter.WinChangeCall)
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			_, _ = fmt.Printf("\r%s\n\n\r", sessErr)
			return
		}
		if _, _, err = session.sendRequest(
			"disconnect",
			true,
			nil,
		); err != nil {
			_, _ = fmt.Printf("\r%s\n\r", err)
			return
		}
		_, _ = fmt.Printf("\rSessionID %d shutdown gracefully\n\r", *sKill)
		return
	}
}

func (s *server) cmdSocks(args ...string) {
	socksCmd := flag.NewFlagSet("socks", flag.ContinueOnError)
	id := socksCmd.Int("s", 0, "Run socks5 server over a Session ID Channel")
	sp := socksCmd.Int("p", 0, "Run socks5 server over a Session ID Channel")
	sk := socksCmd.Int("k", 0, "Kill Session ID SOCKS5 Endpoint and Server")

	socksCmd.SetOutput(s.console)

	if pErr := socksCmd.Parse(args); pErr != nil {
		return
	}

	if *id == 0 && *sk == 0 {
		socksCmd.Usage()
		return
	}

	if *sk > 0 {
		session, sessErr := s.getSession(*sk)
		if sessErr != nil {
			fmt.Printf("\rUnknown Session ID %d\n\r", *sk)
			return
		}
		if session.SocksInstance.IsEnabled() {
			if err := session.SocksInstance.Stop(); err != nil {
				fmt.Printf("\r[!] %s\n\r", err)
				return
			}
			fmt.Printf("\r[+] Socks Endpoint gracefully stopped\n")
			return
		}
		fmt.Printf("\rSocks is not running on Session ID %d\r\n", *sk)
		return
	}

	if *id > 0 {
		session, sessErr := s.getSession(*id)
		if sessErr != nil {
			fmt.Printf("\rUnknown Session ID %d\n\r", *id)
			return
		}
		fmt.Printf("\r[*] Enabling Socks5 Endpoint in the background\r\n")

		go session.socksEnable(*sp)

		// Give some time to check
		timeout := time.Now().Add(5 * time.Second)
		for time.Now().Before(timeout) {
			port, _ := session.SocksInstance.GetEndpointPort()
			if port == 0 {
				time.Sleep(250 * time.Millisecond)
				continue
			}
			fmt.Printf("\r[+] Socks Endpoint running on port \"%d\"\r\n", port)
			return
		}
		fmt.Printf("\r[!] Socks Endpoint doesn't appear to be running\r\n")
		return
	}
	socksCmd.Usage()
}

func (s *server) cmdUpload(args ...string) {
	uploadCmd := flag.NewFlagSet("upload", flag.ContinueOnError)
	id := uploadCmd.Int("s", 0, "Run sftp test over a Session ID Channel")

	uploadCmd.SetOutput(s.console)

	if pErr := uploadCmd.Parse(args); pErr != nil {
		return
	}

	if len(uploadCmd.Args()) > 2 || len(uploadCmd.Args()) < 1 {
		fmt.Printf("\rIncorrect number of arguments\r\n")
		return
	}

	if *id > 0 {
		session, sessErr := s.getSession(*id)
		if sessErr != nil {
			fmt.Printf("\rUnknown Session ID %d\n\r", *id)
			return
		}

		src := uploadCmd.Args()[0]
		dst := filepath.Base(src)
		if len(uploadCmd.Args()) == 2 {
			dst = uploadCmd.Args()[1]
		}

		for statusChan := range session.uploadFile(src, dst) {
			if statusChan.Success {
				fmt.Printf(
					"\r[+] Uploaded \"%s\" -> \"%s\" (sha256:%s)\r\n",
					src,
					statusChan.FileName,
					statusChan.CheckSum,
				)
			} else {
				fmt.Printf("\r[!] Failed to Upload \"%s\": %s\r\n", src, statusChan.Err)
			}
		}
	}
}

func (s *server) cmdDownload(args ...string) {
	downloadCmd := flag.NewFlagSet("download", flag.ContinueOnError)
	id := downloadCmd.Int("s", 0, "Run sftp test over a Session ID Channel")
	dl := downloadCmd.String("l", "", "Run sftp test over a Session ID Channel")

	downloadCmd.SetOutput(s.console)

	if pErr := downloadCmd.Parse(args); pErr != nil {
		return
	}

	if *id == 0 {
		fmt.Printf("\rIncorrect number of arguments\r\n")
		return
	}

	if *id > 0 {
		session, sessErr := s.getSession(*id)
		if sessErr != nil {
			fmt.Printf("\rUnknown Session ID %d\n\r", *id)
			return
		}

		if *dl == "" && downloadCmd.NFlag() >= 2 {
			fmt.Printf("\rNeed to provide a list file\n\r")
			return
		} else if *dl != "" {
			fmt.Printf("\rOutput Dir: \"%s\"", sio.GetOutputDir())
			for statusChan := range session.downloadFileBatch(*dl) {
				if statusChan.Success {
					fmt.Printf(
						"\r[+] Downloaded \"%s\" (sha256:%s)\r\n",
						statusChan.FileName,
						statusChan.CheckSum,
					)
				} else {
					fmt.Printf("\r[!] Failed to Download \"%s\"\r\n", statusChan.Err)
				}
			}
			return
		}

		if len(downloadCmd.Args()) > 2 || len(downloadCmd.Args()) < 1 {
			fmt.Printf("\rIncorrect number of arguments\r\n")
			return
		}

		src := downloadCmd.Args()[0]
		dst := filepath.Base(src)
		if len(downloadCmd.Args()) == 2 {
			dst = downloadCmd.Args()[1]
		}

		for statusChan := range session.downloadFile(src, dst) {
			if statusChan.Success {
				fmt.Printf(
					"\r[+] Downloaded \"%s\" -> \"%s\" (sha256:%s)\r\n",
					src,
					statusChan.FileName,
					statusChan.CheckSum,
				)
			} else {
				fmt.Printf("\r[!] Failed to Download \"%s\": %s\r\n", src, statusChan.Err)
			}
		}
	}
}
