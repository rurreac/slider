package server

import (
	"fmt"
	"slider/pkg/spath"
)

const (
	pwdCmd   = "pwd"
	pwdDesc  = "Print remote working directory"
	lPwdCmd  = "lpwd"
	lPwdDesc = "Print local working directory"
)

// SftpPwdCommand implements the 'pwd' command
type SftpPwdCommand struct {
	isRemote bool
}

func (c *SftpPwdCommand) Name() string {
	if c.isRemote {
		return pwdCmd
	}
	return lPwdCmd
}

func (c *SftpPwdCommand) Description() string {
	if c.isRemote {
		return pwdDesc
	}
	return lPwdDesc
}

func (c *SftpPwdCommand) Usage() string {
	return c.Name()
}

func (c *SftpPwdCommand) IsRemote() bool {
	return c.isRemote
}

func (c *SftpPwdCommand) IsRemoteCompletion() bool { return c.isRemote }

func (c *SftpPwdCommand) Run(execCtx *ExecutionContext, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many arguments")
	}

	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	cwd := sftpCtx.getCwd(c.isRemote)

	// Display path in native format for user
	displayPath := cwd
	if c.isRemote {
		system := sftpCtx.getContextSystem(c.isRemote)
		displayPath = spath.NormalizeToSystemPath(cwd, system)
	}

	execCtx.UI().Printf("%s\n\n", displayPath)
	return nil
}
