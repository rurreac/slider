package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slider/pkg/spath"
	"text/tabwriter"

	"github.com/pkg/sftp"
	"github.com/spf13/pflag"
)

const (
	statCmd   = "stat"
	statDesc  = "Display remote file information"
	statUsage = "stat <path>"
)

// SftpStatCommand implements the 'stat' command (remote only)
type SftpStatCommand struct{}

func (c *SftpStatCommand) Name() string             { return statCmd }
func (c *SftpStatCommand) Description() string      { return statDesc }
func (c *SftpStatCommand) Usage() string            { return statUsage }
func (c *SftpStatCommand) IsRemote() bool           { return true }
func (c *SftpStatCommand) IsRemoteCompletion() bool { return true }

func (c *SftpStatCommand) Run(execCtx *ExecutionContext, args []string) error {
	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}
	ui := execCtx.UI()

	statFlags := pflag.NewFlagSet(statCmd, pflag.ContinueOnError)
	statFlags.SetOutput(ui.Writer())

	statFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", statUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", statDesc)
		statFlags.PrintDefaults()
	}

	if pErr := statFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
	}

	if statFlags.NArg() != 1 {
		return fmt.Errorf("exactly 1 argument required, got %d", statFlags.NArg())
	}

	path := statFlags.Args()[0]
	if !spath.IsAbs(sftpCtx.RemoteSystem(), path) {
		path = spath.Join(sftpCtx.RemoteSystem(), []string{sftpCtx.GetRemoteCwd(), path})
	}

	// Get file info
	fi, err := sftpCtx.sftpCli.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}

	// Determine file type
	fileType := "Regular File"
	if fi.IsDir() {
		fileType = "Directory"
	} else if fi.Mode()&os.ModeSymlink != 0 {
		fileType = "Symbolic Link"
	} else if fi.Mode()&os.ModeDevice != 0 {
		fileType = "Device"
	} else if fi.Mode()&os.ModeNamedPipe != 0 {
		fileType = "Named Pipe"
	} else if fi.Mode()&os.ModeSocket != 0 {
		fileType = "Socket"
	}

	// Format file size
	sizeStr := ""
	if fi.IsDir() {
		sizeStr = "<DIR>"
	} else {
		bytesSize := fi.Size()
		if bytesSize < 1024 {
			sizeStr = fmt.Sprintf("%d B", bytesSize)
		} else if bytesSize < 1024*1024 {
			sizeStr = fmt.Sprintf("%.2f KB (%.0f bytes)", float64(bytesSize)/1024, float64(bytesSize))
		} else if bytesSize < 1024*1024*1024 {
			sizeStr = fmt.Sprintf("%.2f MB (%.0f bytes)", float64(bytesSize)/(1024*1024), float64(bytesSize))
		} else {
			sizeStr = fmt.Sprintf("%.2f GB (%.0f bytes)", float64(bytesSize)/(1024*1024*1024), float64(bytesSize))
		}
	}

	// Print file information
	ui.PrintSuccess("File Information for: %s\n", path)
	tw := new(tabwriter.Writer)
	tw.Init(ui.Writer(), 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\tName:\t%s\n", filepath.Base(path))
	_, _ = fmt.Fprintf(tw, "\tType:\t%s\n", fileType)
	_, _ = fmt.Fprintf(tw, "\tSize:\t%s\n", sizeStr)
	_, _ = fmt.Fprintf(tw, "\tPermissions:\t%s (%04o)\n", fi.Mode().String(), fi.Mode().Perm())
	_, _ = fmt.Fprintf(tw, "\tModified:\t%s\n", fi.ModTime().Format("Jan 02, 2006 15:04:05 MST"))

	// Try to get extended information
	if sftpStat, ok := fi.Sys().(*sftp.FileStat); ok && sftpCtx.RemoteSystem() != "windows" {
		_, _ = fmt.Fprintf(tw, "\tOwner UID:\t%d\n", sftpStat.UID)
		_, _ = fmt.Fprintf(tw, "\tGroup GID:\t%d\n", sftpStat.GID)
	}
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()

	return nil
}
