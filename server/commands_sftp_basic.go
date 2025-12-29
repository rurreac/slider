package server

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

// SftpHelpCommand implements the 'help' command for SFTP console
type SftpHelpCommand struct{}

func (c *SftpHelpCommand) Name() string             { return helpCmd }
func (c *SftpHelpCommand) Description() string      { return helpDesc }
func (c *SftpHelpCommand) Usage() string            { return helpCmd }
func (c *SftpHelpCommand) IsRemote() bool           { return false }
func (c *SftpHelpCommand) IsRemoteCompletion() bool { return false }
func (c *SftpHelpCommand) Run(ctx *ExecutionContext, _ []string) error {
	session, err := ctx.RequireSession()
	if err != nil {
		return err
	}
	ui := ctx.UI()

	tw := new(tabwriter.Writer)
	tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommand\tDescription\t")
	_, _ = fmt.Fprintf(tw, "\n\t-------\t-----------\t\n")

	// Get primary commands with their aliases
	primaryCommands := session.sftpCommandRegistry.GetPrimaryCommands()

	// Create a sorted list of primary command names
	var cmdNames []string
	for cmdName := range primaryCommands {
		cmdNames = append(cmdNames, cmdName)
	}
	sort.Strings(cmdNames)

	for _, cmdName := range cmdNames {
		if cmd, ok := session.sftpCommandRegistry.Get(cmdName); ok {
			aliases := primaryCommands[cmdName]
			aliasStr := strings.Join(aliases, ", ")
			_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", aliasStr, cmd.Description())
		}
	}

	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", "execute", "Execute command on remote system")
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", "shell", "Enter interactive shell")
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", "!command", "Execute \"command\" in local shell (non-interactive)")
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
	return nil
}

// SftpExitCommand implements the 'exit' command for SFTP
type SftpExitCommand struct{}

func (c *SftpExitCommand) Name() string             { return exitCmd }
func (c *SftpExitCommand) Description() string      { return exitDesc }
func (c *SftpExitCommand) Usage() string            { return exitCmd }
func (c *SftpExitCommand) IsRemote() bool           { return false }
func (c *SftpExitCommand) IsRemoteCompletion() bool { return false }
func (c *SftpExitCommand) Run(_ *ExecutionContext, _ []string) error {
	return ErrExitConsole
}
