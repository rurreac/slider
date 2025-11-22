package server

import (
	"fmt"
	"text/tabwriter"
)

const (
	// Console Basic Commands
	bgCmd    = "bg"
	bgDesc   = "Puts Console into background and returns to logging output"
	exitCmd  = "exit"
	exitDesc = "Exits Console and terminates the Server"
	helpCmd  = "help"
	helpDesc = "Shows this output"
)

// BgCommand implements the 'bg' command
type BgCommand struct{}

func (c *BgCommand) Name() string        { return bgCmd }
func (c *BgCommand) Description() string { return bgDesc }
func (c *BgCommand) Usage() string       { return bgCmd }
func (c *BgCommand) Run(s *server, args []string, ui UserInterface) error {
	s.console.PrintlnInfo("Logging...\n\r")
	return ErrBackgroundConsole
}

// ExitCommand implements the 'exit' command
type ExitCommand struct{}

func (c *ExitCommand) Name() string        { return exitCmd }
func (c *ExitCommand) Description() string { return exitDesc }
func (c *ExitCommand) Usage() string       { return exitCmd }
func (c *ExitCommand) Run(s *server, args []string, ui UserInterface) error {
	return ErrExitConsole
}

// HelpCommand implements the 'help' command
type HelpCommand struct{}

func (c *HelpCommand) Name() string        { return helpCmd }
func (c *HelpCommand) Description() string { return helpDesc }
func (c *HelpCommand) Usage() string       { return helpCmd }
func (c *HelpCommand) Run(s *server, args []string, ui UserInterface) error {
	tw := new(tabwriter.Writer)
	tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommand\tDescription\t")
	_, _ = fmt.Fprintf(tw, "\n\t-------\t-----------\t\n")

	// We need access to the registry. Since it's on the server struct, we can access it.
	// Note: This assumes we will add CommandRegistry to the server struct.
	cmdNames := s.commandRegistry.List()

	for _, cmdName := range cmdNames {
		if cmd, ok := s.commandRegistry.Get(cmdName); ok {
			_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", cmdName, cmd.Description())
		}
	}
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", "!command", "Execute \"command\" in local shell (non-interactive)")
	_, _ = fmt.Fprintln(tw)
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
	return nil
}
