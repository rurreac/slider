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

func (c *SftpPwdCommand) Run(server *server, args []string, ui UserInterface) error {
	return nil
}

func (c *SftpPwdCommand) RunSftp(session *Session, args []string, ui UserInterface) error {
	if len(args) > 0 {
		return fmt.Errorf("too many arguments")
	}

	ctx := session.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	cwd := ctx.getCwd(c.isRemote)

	ui.Printf("%s\n\n", cwd)
	return nil
}
