package server

import (
	"fmt"
	"text/tabwriter"
)

const (
	sysInfoCmd  = "sysinfo"
	sysInfoDesc = "Display system information"
)

// SftpSysInfoCommand implements the 'sysinfo' command
type SftpSysInfoCommand struct{}

func (c *SftpSysInfoCommand) Name() string             { return sysInfoCmd }
func (c *SftpSysInfoCommand) Description() string      { return sysInfoDesc }
func (c *SftpSysInfoCommand) Usage() string            { return sysInfoCmd }
func (c *SftpSysInfoCommand) IsRemote() bool           { return true }
func (c *SftpSysInfoCommand) IsRemoteCompletion() bool { return false }

func (c *SftpSysInfoCommand) Run(ctx *ExecutionContext, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sysinfo command does not accept arguments")
	}

	session, err := ctx.RequireSession()
	if err != nil {
		return err
	}

	sftpCtx := session.GetSftpContext().(*SftpCommandContext)
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	interpreter := sftpCtx.remoteInterpreter
	if interpreter == nil {
		interpreter = session.GetInterpreter()
	}

	if interpreter == nil {
		return fmt.Errorf("failed to resolve interpreter information")
	}

	ui := ctx.UI()
	tw := new(tabwriter.Writer)
	tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)

	_, _ = fmt.Fprintf(tw, "\n\tProperty\tValue\t")
	_, _ = fmt.Fprintf(tw, "\n\t--------\t-----\t\n")
	_, _ = fmt.Fprintf(tw, "\tSystem\t%s\t\n", interpreter.System)
	_, _ = fmt.Fprintf(tw, "\tArchitecture\t%s\t\n", interpreter.Arch)
	_, _ = fmt.Fprintf(tw, "\tUser\t%s\t\n", interpreter.User)
	_, _ = fmt.Fprintf(tw, "\tBinary Path\t%s\t\n", interpreter.SliderDir)
	_, _ = fmt.Fprintf(tw, "\tLaunch Path\t%s\t\n", interpreter.LaunchDir)
	_, _ = fmt.Fprintf(tw, "\tHome Directory\t%s\t\n", interpreter.HomeDir)
	_, _ = fmt.Fprintf(tw, "\tWorking Directory\t%s\t\n", *sftpCtx.remoteCwd)
	_, _ = fmt.Fprintln(tw)

	return tw.Flush()
}
