package server

import (
	"fmt"
	"slider/pkg/spath"
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

func (c *SftpSysInfoCommand) Run(execCtx *ExecutionContext, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("sysinfo command does not accept arguments")
	}

	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	remoteInfo := sftpCtx.remoteInfo

	ui := execCtx.UI()
	tw := new(tabwriter.Writer)
	tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)

	_, _ = fmt.Fprintf(tw, "\n\tProperty\tValue\t")
	_, _ = fmt.Fprintf(tw, "\n\t--------\t-----\t\n")
	_, _ = fmt.Fprintf(tw, "\tSystem\t%s\t\n", remoteInfo.System)
	_, _ = fmt.Fprintf(tw, "\tArchitecture\t%s\t\n", remoteInfo.Arch)
	_, _ = fmt.Fprintf(tw, "\tUser\t%s\t\n", remoteInfo.User)
	_, _ = fmt.Fprintf(tw, "\tBinary Path\t%s\t\n", remoteInfo.SliderDir)
	_, _ = fmt.Fprintf(tw, "\tLaunch Path\t%s\t\n", remoteInfo.LaunchDir)
	_, _ = fmt.Fprintf(tw, "\tHome Directory\t%s\t\n", spath.NormalizeToSystemPath(remoteInfo.HomeDir, remoteInfo.System))
	_, _ = fmt.Fprintf(tw, "\tWorking Directory\t%s\t\n", spath.NormalizeToSystemPath(sftpCtx.GetRemoteCwd(), remoteInfo.System))
	_, _ = fmt.Fprintln(tw)

	return tw.Flush()
}
