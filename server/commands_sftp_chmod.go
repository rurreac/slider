package server

import (
	"errors"
	"fmt"
	"os"
	"slider/pkg/spath"
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

const (
	chmodCmd   = "chmod"
	chmodDesc  = "Change remote file permissions"
	chmodUsage = "chmod <mode> <path>"
)

// SftpChmodCommand implements the 'chmod' command (remote only, non-Windows)
type SftpChmodCommand struct{}

func (c *SftpChmodCommand) Name() string             { return chmodCmd }
func (c *SftpChmodCommand) Description() string      { return chmodDesc }
func (c *SftpChmodCommand) Usage() string            { return chmodUsage }
func (c *SftpChmodCommand) IsRemote() bool           { return true }
func (c *SftpChmodCommand) IsRemoteCompletion() bool { return true }

func (c *SftpChmodCommand) Run(execCtx *ExecutionContext, args []string) error {
	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}
	ui := execCtx.UI()

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
		return pErr
	}

	// Validate exact args
	if chmodFlags.NArg() != 2 {
		return fmt.Errorf("exactly 2 arguments required, got %d", chmodFlags.NArg())
	}

	modeStr := chmodFlags.Args()[0]
	path := chmodFlags.Args()[1]

	// Handle relative path
	if !spath.IsAbs(sftpCtx.RemoteSystem(), path) {
		path = spath.Join(sftpCtx.RemoteSystem(), []string{sftpCtx.GetRemoteCwd(), path})
	}

	// Parse mode
	var mode os.FileMode
	if strings.HasPrefix(modeStr, "0") {
		// Octal mode
		modeInt, parseErr := strconv.ParseUint(modeStr, 8, 32)
		if parseErr != nil {
			return fmt.Errorf("invalid permission format (use octal, e.g. 0755): %w", parseErr)
		}
		mode = os.FileMode(modeInt)
	} else {
		// Decimal mode
		modeInt, parseErr := strconv.ParseUint(modeStr, 10, 32)
		if parseErr != nil {
			return fmt.Errorf("invalid permission format: %w", parseErr)
		}
		mode = os.FileMode(modeInt)
	}

	// Check if file exists
	_, statErr := sftpCtx.sftpCli.Stat(path)
	if statErr != nil {
		return fmt.Errorf("file or directory \"%s\" not found: %w", path, statErr)
	}

	// Change permissions
	err := sftpCtx.sftpCli.Chmod(path, mode)
	if err != nil {
		return fmt.Errorf("failed to change \"%s\" permissions: %w", path, err)
	}

	ui.PrintSuccess("Changed permissions of %s to %s (%s)",
		path,
		modeStr,
		mode.String())

	return nil
}
