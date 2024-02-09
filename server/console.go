package server

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"golang.org/x/term"
)

func (s *server) NewConsole() string {
	var out string

	s.consoleState, _ = term.MakeRaw(int(os.Stdin.Fd()))
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.consoleState)
	}()

	screen := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}
	s.console = term.NewTerminal(screen, "")

	fmt.Printf("\r\n\rType \"bg\" to background the console or \"exit\" to terminate the server.\n\n\r")
	s.console.SetPrompt("\rSlider" + string(s.console.Escape.Cyan) + ">" + string(s.console.Escape.Reset) + " ")

	cf := flag.NewFlagSet("Console Command", flag.ContinueOnError)

	for consoleInput := true; consoleInput; {
		input, err := s.console.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.Errorf("Failed to read input %s", err)
			}
			consoleInput = false
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)
		_ = cf.Parse(args)
		consoleCmd := cf.Args()

		if len(consoleCmd) > 0 {
			out = consoleCmd[0]
			switch out {
			case "exit", "bg":
				consoleInput = false
			default:
				s.processCommand(consoleCmd)
			}
		}
	}
	return out
}

func (s *server) processCommand(consoleCmd []string) {
	command := consoleCmd[0]
	args := consoleCmd[1:]

	switch command {
	case "sessions":
		s.cmdSessions(args...)
	case "help":
		s.help()
	default:
		fmt.Printf("Not recognized Command: %s, Arguments %s\n", command, args)
		s.help()
	}
}

func (s *server) help() {
	s.cmdSessions()
}

func (s *server) cmdSessions(args ...string) {
	sFlag := flag.NewFlagSet("\"sessions\" Command", flag.ContinueOnError)
	sFlag.SetOutput(s.console)

	sl := sFlag.Bool("l", false, "List Server Sessions")
	si := sFlag.Int("i", 0, "Start Interactive Shell on Session ID")
	_ = sFlag.Parse(args)

	if (len(sFlag.Args()) > 0 || len(args) == 0) || (*sl && *si > 0) {
		params := ""
		if len(args) > 0 {
			params = fmt.Sprintf("Received unwanted parammeters: %v\n", sFlag.Args())
		}
		_, _ = fmt.Fprintf(
			s.console,
			"%ssessions - interact with sessions:\n",
			params,
		)
		sFlag.PrintDefaults()
		return
	}

	if *sl {
		if len(s.sessionTrack.Sessions) > 0 {
			tw := new(tabwriter.Writer)
			tw.Init(s.console, 0, 4, 2, ' ', tabwriter.AlignRight)
			_, _ = fmt.Println()
			_, _ = fmt.Fprintln(tw, "\tSessionID\tAddress\t")

			for sID, session := range s.sessionTrack.Sessions {
				_, _ = fmt.Fprintf(tw, "\t%d\t%s\t\n",
					sID,
					session.shellWsConn.RemoteAddr().String())
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		_, _ = fmt.Fprintf(s.console, "Active sessions: %d\n\n", s.sessionTrack.SessionActive)
		return
	}
	if *si > 0 {
		s.SessionInteractive(*si)
	}
}
