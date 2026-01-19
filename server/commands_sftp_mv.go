package server

import (
	"errors"
	"fmt"
	"slider/pkg/spath"

	"github.com/spf13/pflag"
)

const (
	mvCmd   = "mv"
	mvDesc  = "Move or rename remote file/directory"
	mvUsage = "mv <source> <destination>"
)

// SftpMvCommand implements the 'mv' command (remote only)
type SftpMvCommand struct{}

func (c *SftpMvCommand) Name() string             { return mvCmd }
func (c *SftpMvCommand) Description() string      { return mvDesc }
func (c *SftpMvCommand) Usage() string            { return mvUsage }
func (c *SftpMvCommand) IsRemote() bool           { return true }
func (c *SftpMvCommand) IsRemoteCompletion() bool { return true }

func (c *SftpMvCommand) Run(execCtx *ExecutionContext, args []string) error {
	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}
	ui := execCtx.UI()

	mvFlags := pflag.NewFlagSet(mvCmd, pflag.ContinueOnError)
	mvFlags.SetOutput(ui.Writer())

	mvFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n", mvDesc)
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", mvUsage)
		mvFlags.PrintDefaults()
	}

	if pErr := mvFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
	}

	if mvFlags.NArg() != 2 {
		return fmt.Errorf("exactly 2 arguments required, got %d", mvFlags.NArg())
	}

	srcPath := mvFlags.Args()[0]
	dstPath := mvFlags.Args()[1]

	// Handle relative paths
	remoteSystem := sftpCtx.RemoteSystem()
	if !spath.IsAbs(remoteSystem, srcPath) {
		srcPath = spath.Join(remoteSystem, []string{sftpCtx.GetRemoteCwd(), srcPath})
	}
	if !spath.IsAbs(remoteSystem, dstPath) {
		dstPath = spath.Join(remoteSystem, []string{sftpCtx.GetRemoteCwd(), dstPath})
	}

	// Check if source exists
	srcFi, err := sftpCtx.sftpCli.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("source file or directory \"%s\" not found: %w", srcPath, err)
	}

	// Check if destination already exists
	_, err = sftpCtx.sftpCli.Stat(dstPath)
	if err == nil {
		return fmt.Errorf("destination already exists, cannot overwrite")
	}

	// Rename file or directory
	err = sftpCtx.sftpCli.Rename(srcPath, dstPath)
	if err != nil {
		return fmt.Errorf("failed to rename \"%s\": %w", srcPath, err)
	}

	if srcFi.IsDir() {
		ui.PrintSuccess("Renamed directory from %s to %s", srcPath, dstPath)
	} else {
		ui.PrintSuccess("Renamed file from %s to %s", srcPath, dstPath)
	}

	return nil
}
