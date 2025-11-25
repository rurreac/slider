package server

import (
	"fmt"
	"slider/pkg/spath"
)

const (
	cdCmd   = "cd"
	cdDesc  = "Change remote directory"
	lcdCmd  = "lcd"
	lcdDesc = "Change local directory"
)

// SftpCdCommand implements the 'cd' and 'lcd' commands
type SftpCdCommand struct {
	isRemote bool
}

func (c *SftpCdCommand) Name() string {
	if c.isRemote {
		return cdCmd
	}
	return lcdCmd
}

func (c *SftpCdCommand) Description() string {
	if c.isRemote {
		return cdDesc
	}
	return lcdDesc
}

func (c *SftpCdCommand) Usage() string {
	return fmt.Sprintf("Usage: %s [directory]", c.Name())
}

func (c *SftpCdCommand) IsRemote() bool {
	return c.isRemote
}

func (c *SftpCdCommand) Run(ctx *ExecutionContext, args []string) error {
	session, err := ctx.RequireSession()
	if err != nil {
		return err
	}
	ui := ctx.UI()
	sftpCtx := session.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	// No args - go to home directory
	if len(args) < 1 {
		sftpCtx.getCwd(c.isRemote)
		return nil
	}

	if len(args) > 1 {
		return fmt.Errorf("too many arguments")
	}

	newPath := args[0]

	// Handle "." (current directory) - no change needed
	if newPath == "." {
		return nil
	}

	// Get current working directory
	cwd := sftpCtx.getCwd(c.isRemote)
	system := sftpCtx.getContextSystem(c.isRemote)

	// Handle ".." (parent directory)
	if newPath == ".." {
		parentPath := spath.Dir(system, cwd)
		if parentPath == cwd {
			// Already at root
			return nil
		}
		newPath = parentPath
	} else if !spath.IsAbs(system, newPath) {
		// Relative path, join with current directory
		newPath = spath.Join(system, []string{cwd, newPath})
	}

	// Check if directory exists and is accessible
	stat, err := sftpCtx.pathStat(newPath, c.isRemote)
	if err != nil {
		return fmt.Errorf("failed to stat \"%s\": %w", newPath, err)
	}
	if stat == nil {
		return fmt.Errorf("directory \"%s\" does not exist", newPath)
	}
	if !stat.IsDir() {
		return fmt.Errorf("not a directory: %s", newPath)
	}

	// Update the current directory
	sftpCtx.setCwd(newPath, c.isRemote)
	ui.PrintSuccess("Current %s path: %s", c.Name(), newPath)

	return nil
}
