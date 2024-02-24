package server

import (
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
	"os/exec"
	"slider/pkg/interpreter"
	"strings"
	"text/tabwriter"
)

func (s *server) NewConsole() string {
	var out string

	// Set Interpreter
	if s.sInterpreter == nil {
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
		case "help":
			s.cmdSessions()
			s.cmdExecute()
		case "":
			continue
		default:
			s.notConsoleCmd(args)
		}
	}

	return out
}

func (s *server) setInterpreter(i *interpreter.Interpreter) {
	s.sInterpreter = i
}

func (s *server) notConsoleCmd(fCmd []string) {
	_, _ = fmt.Printf(
		"\r%sConsole does not recognize Command: %s%s\n",
		string(s.console.Escape.Yellow),
		string(s.console.Escape.Reset),
		fCmd,
	)

	// If a Shell was not set just return
	if s.sInterpreter.Shell == "" {
		return
	}

	// Else, we'll try to execute the command locally
	fCmd = append(s.sInterpreter.CmdArgs, strings.Join(fCmd, " "))

	_, _ = fmt.Printf(
		"\r%sWill run an OS command locally instead...%s\n\r",
		string(s.console.Escape.Yellow),
		string(s.console.Escape.Reset),
	)

	cmd := exec.Command(s.sInterpreter.Shell, fCmd...) //nolint:gosec
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
		if _, _, err := session.sendRequestAndRetry(
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
			_, _ = fmt.Fprintln(tw, "\n\tSessionID\tAddress\t")

			for sID, session := range s.sessionTrack.Sessions {
				_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n",
					sID,
					session.shellWsConn.RemoteAddr().String())
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
		if _, _, err = session.sendRequestAndRetry(
			"session-shell",
			true,
			nil,
		); err != nil {
			_, _ = fmt.Printf("\r%s\n\n\r", err)
			return
		}
		session.sessionInteractive(s.consoleState, s.console, s.sInterpreter.WinChangeCall)
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			_, _ = fmt.Printf("\r%s\n\n\r", sessErr)
			return
		}
		if _, _, err = session.sendRequestAndRetry(
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
