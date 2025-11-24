package server

import (
	"errors"
	"fmt"
	"os"
	"slider/pkg/spath"
	"strconv"

	"github.com/spf13/pflag"
)

const (
	chmodCmd   = "chmod"
	chmodDesc  = "Change remote file permissions"
	chmodUsage = "chmod <mode> <path>"
)

// SftpChmodCommand implements the 'chmod' command (remote only, non-Windows)
type SftpChmodCommand struct{}

func (c *SftpChmodCommand) Name() string        { return chmodCmd }
func (c *SftpChmodCommand) Description() string { return chmodDesc }
func (c *SftpChmodCommand) Usage() string       { return chmodUsage }
func (c *SftpChmodCommand) IsRemote() bool      { return true }

func (c *SftpChmodCommand) Run(s *server, args []string, ui UserInterface) error {
	ctx := s.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	chmodFlags := pflag.NewFlagSet(chmodCmd, pflag.ContinueOnError)
	chmodFlags.SetOutput(ui.Writer())

	chmodFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", chmodUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", chmodDesc)
		chmodFlags.PrintDefaults()
	}

	if pErr := chmodFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flag error: %w", pErr)
	}

	// Validate exact args
	if chmodFlags.NArg() != 2 {
		return fmt.Errorf("exactly 2 arguments required, got %d", chmodFlags.NArg())
	}

	modeStr := chmodFlags.Args()[0]
	path := chmodFlags.Args()[1]

	// Handle relative path
	if !spath.IsAbs(ctx.cliSystem, path) {
		path = spath.Join(ctx.cliSystem, []string{*ctx.remoteCwd, path})
	}

	// Parse octal mode
	var mode uint64
	var err error
	if len(modeStr) > 0 && modeStr[0] == '0' {
		// Parse as octal with leading zero
		mode, err = strconv.ParseUint(modeStr, 8, 32)
	} else {
		// Parse as decimal if no leading zero
		mode, err = strconv.ParseUint(modeStr, 10, 32)
	}

	if err != nil {
		return fmt.Errorf("invalid permission format (use octal, e.g. 0755): %w", err)
	}

	// Check if file exists
	_, err = ctx.sftpCli.Stat(path)
	if err != nil {
		return fmt.Errorf("file or directory \"%s\" not found: %w", path, err)
	}

	// Change permissions
	err = ctx.sftpCli.Chmod(path, os.FileMode(mode))
	if err != nil {
		return fmt.Errorf("failed to change \"%s\" permissions: %w", path, err)
	}

	ui.PrintSuccess("Changed permissions of %s to %s (%s)",
		path,
		modeStr,
		os.FileMode(mode).String())

	return nil
}
