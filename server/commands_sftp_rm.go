package server

import (
	"errors"
	"fmt"
	"os"
	"slider/pkg/spath"

	"github.com/spf13/pflag"
)

const (
	rmCmd   = "rm"
	rmDesc  = "Remove remote file or directory"
	rmUsage = "rm [-r] <path>"
)

// SftpRmCommand implements the 'rm' command (remote only)
type SftpRmCommand struct{}

func (c *SftpRmCommand) Name() string        { return rmCmd }
func (c *SftpRmCommand) Description() string { return rmDesc }
func (c *SftpRmCommand) Usage() string       { return rmUsage }
func (c *SftpRmCommand) IsRemote() bool      { return true }

func (c *SftpRmCommand) Run(ctx *ExecutionContext, args []string) error {
	session, err := ctx.RequireSession()
	if err != nil {
		return err
	}
	ui := ctx.UI()
	sftpCtx := session.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	rmFlags := pflag.NewFlagSet(rmCmd, pflag.ContinueOnError)
	rmFlags.SetOutput(ui.Writer())

	recursive := rmFlags.BoolP("recursive", "r", false, "Remove directory and their contents recursively")

	rmFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", rmUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", rmDesc)
		rmFlags.PrintDefaults()
	}

	if pErr := rmFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flag error: %w", pErr)
	}

	if rmFlags.NArg() != 1 {
		return fmt.Errorf("exactly 1 argument required, got %d", rmFlags.NArg())
	}

	path := rmFlags.Args()[0]
	if !spath.IsAbs(sftpCtx.cliSystem, path) {
		path = spath.Join(sftpCtx.cliSystem, []string{*sftpCtx.remoteCwd, path})
	}

	// Check if path exists
	fi, sErr := sftpCtx.sftpCli.Stat(path)
	if sErr != nil {
		return fmt.Errorf("file or directory not found")
	}

	if fi.IsDir() {
		if *recursive {
			// Perform recursive removal using SFTP RemoveAll
			// Note: pkg/sftp doesn't have RemoveAll, so we need to implement it
			err := removeDirectoryRecursive(sftpCtx.sftpCli, path)
			if err != nil {
				return fmt.Errorf("failed to remove directory recursively: %w", err)
			}
			ui.PrintSuccess("Removed directory: %s\n", path)
		} else {
			// Try to remove empty directory
			rdErr := sftpCtx.sftpCli.RemoveDirectory(path)
			if rdErr != nil {
				return fmt.Errorf("directory is not empty (use '-r' flag)")
			}
			ui.PrintSuccess("Removed empty directory: %s\n", path)
		}
	} else {
		// It's a file
		rmErr := sftpCtx.sftpCli.Remove(path)
		if rmErr != nil {
			return fmt.Errorf("failed to remove file: %w", rmErr)
		}
		ui.PrintSuccess("Removed file: %s\n", path)
	}

	return nil
}

// removeDirectoryRecursive removes a directory and all its contents recursively
func removeDirectoryRecursive(sftpCli interface {
	ReadDir(string) ([]os.FileInfo, error)
	Remove(string) error
	RemoveDirectory(string) error
}, path string) error {
	// Read directory contents
	entries, err := sftpCli.ReadDir(path)
	if err != nil {
		return err
	}

	// Remove all entries
	for _, entry := range entries {
		fullPath := path + "/" + entry.Name()
		if entry.IsDir() {
			// Recursively remove subdirectory
			if err := removeDirectoryRecursive(sftpCli, fullPath); err != nil {
				return err
			}
		} else {
			// Remove file
			if err := sftpCli.Remove(fullPath); err != nil {
				return err
			}
		}
	}

	// Remove the now-empty directory
	return sftpCli.RemoveDirectory(path)
}
