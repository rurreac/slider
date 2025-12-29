package server

import (
	"errors"
	"fmt"
	"slider/pkg/spath"

	"github.com/spf13/pflag"
)

const (
	mkdirCmd    = "mkdir"
	mkdirDesc   = "Create remote directory"
	mkdirUsage  = "mkdir [-p] <directory>"
	lMkdirCmd   = "lmkdir"
	lMkdirDesc  = "Create local directory"
	lMkdirUsage = "lmkdir [-p] <directory>"
)

// SftpMkdirCommand implements the 'mkdir' and 'lmkdir' commands
type SftpMkdirCommand struct {
	isRemote bool
}

func (c *SftpMkdirCommand) Name() string {
	if c.isRemote {
		return mkdirCmd
	}
	return lMkdirCmd
}

func (c *SftpMkdirCommand) Description() string {
	if c.isRemote {
		return mkdirDesc
	}
	return lMkdirDesc
}

func (c *SftpMkdirCommand) Usage() string {
	if c.isRemote {
		return mkdirUsage
	}
	return lMkdirUsage
}

func (c *SftpMkdirCommand) IsRemote() bool { return c.isRemote }

func (c *SftpMkdirCommand) IsRemoteCompletion() bool {
	if !c.isRemote {
		return c.isRemote
	}
	return true
}

func (c *SftpMkdirCommand) Run(ctx *ExecutionContext, args []string) error {
	session, err := ctx.RequireSession()
	if err != nil {
		return err
	}
	ui := ctx.UI()
	sftpCtx := session.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	mkdirFlags := pflag.NewFlagSet(c.Name(), pflag.ContinueOnError)
	mkdirFlags.SetOutput(ui.Writer())

	parents := mkdirFlags.BoolP("parents", "p", false, "Create parent directories as needed")

	mkdirFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", c.Usage())
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", c.Description())
		mkdirFlags.PrintDefaults()
	}

	if pErr := mkdirFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
	}

	if mkdirFlags.NArg() != 1 {
		return fmt.Errorf("exactly 1 argument required, got %d", mkdirFlags.NArg())
	}

	dirPath := mkdirFlags.Args()[0]
	system := sftpCtx.getContextSystem(c.isRemote)
	cwd := sftpCtx.getCwd(c.isRemote)
	if !spath.IsAbs(system, dirPath) {
		dirPath = spath.Join(system, []string{cwd, dirPath})
	}

	// Create the directory
	if err := sftpCtx.pathMkDir(dirPath, c.isRemote, *parents); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	ui.PrintSuccess("Created directory: %s\n", dirPath)
	return nil
}
