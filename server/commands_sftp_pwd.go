package server

import (
	"fmt"
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

func (c *SftpPwdCommand) Run(ctx *ExecutionContext, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("too many arguments")
	}

	session, err := ctx.RequireSession()
	if err != nil {
		return err
	}

	sftpCtx := session.GetSftpContext().(*SftpCommandContext)
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	cwd := sftpCtx.getCwd(c.isRemote)

	ctx.UI().Printf("%s\n\n", cwd)
	return nil
}
