package server

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slider/pkg/spath"

	"github.com/spf13/pflag"
)

const (
	getCmd   = "get"
	getDesc  = "Download file or directory from remote"
	getUsage = "get [-r] <remote_path>"
)

// SftpGetCommand implements the 'get' command for downloading files
type SftpGetCommand struct{}

func (c *SftpGetCommand) Name() string        { return getCmd }
func (c *SftpGetCommand) Description() string { return getDesc }
func (c *SftpGetCommand) Usage() string       { return getUsage }
func (c *SftpGetCommand) IsRemote() bool      { return true }

func (c *SftpGetCommand) Run(server *server, args []string, ui UserInterface) error {
	return nil
}

func (c *SftpGetCommand) RunSftp(session *Session, args []string, ui UserInterface) error {
	ctx := session.sftpContext
	if ctx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}

	getFlags := pflag.NewFlagSet(getCmd, pflag.ContinueOnError)
	getFlags.SetOutput(ui.Writer())

	recursive := getFlags.BoolP("recursive", "r", false, "Download directories recursively")

	getFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", getUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", getDesc)
		getFlags.PrintDefaults()
	}

	if pErr := getFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return fmt.Errorf("flag error: %w", pErr)
	}

	// Validate exact args
	if getFlags.NArg() != 1 {
		return fmt.Errorf("exactly 1 argument required, got %d", getFlags.NArg())
	}

	remotePath := getFlags.Args()[0]
	localPath := *ctx.localCwd

	if !spath.IsAbs(ctx.cliSystem, remotePath) {
		remotePath = spath.Join(ctx.cliSystem, []string{*ctx.remoteCwd, remotePath})
	}

	// Get file info to check if it exists
	rpFi, sErr := ctx.sftpCli.Stat(remotePath)
	if sErr != nil {
		return fmt.Errorf("failed to access remote path: %w", sErr)
	}

	// Handle differently based on whether it's a directory or file
	if rpFi.IsDir() {
		if !*recursive {
			return fmt.Errorf("cannot download a directory without \"-r\" flag")
		}

		// Recursive directory download
		ui.Printf("Downloading directory %s to %s\n", remotePath, localPath)

		// Count files for progress reporting
		fileCount := 0
		totalSize := int64(0)

		// First pass: count files and total size
		wsErr := ctx.walkRemoteDir(remotePath, "", func(rPath, localRelPath string, isDir bool) error {
			if !isDir {
				fileCount++
				fi, err := ctx.sftpCli.Stat(rPath)
				if err != nil {
					return err
				}
				totalSize += fi.Size()
			}
			return nil
		})

		if wsErr != nil {
			return fmt.Errorf("error scanning directory: %w", wsErr)
		}

		ui.Printf("Found %d files totaling %.2f MB\n", fileCount, float64(totalSize)/(1024*1024))

		// Second pass: download files
		currentFile := 0
		downloadedSize := int64(0)

		// Create the target directory for the download
		targetDir := spath.Join(ctx.svrSystem, []string{localPath, spath.Base(ctx.cliSystem, remotePath)})
		if err := ensureLocalDir(targetDir); err != nil {
			return fmt.Errorf("failed to create target directory: %w", err)
		}

		wrdErr := ctx.walkRemoteDir(remotePath, "", func(rPath, localRelPath string, isDir bool) error {
			var localFullPath string
			if localRelPath == "" {
				localFullPath = targetDir
			} else {
				localRelPath = spath.FromToSlash(ctx.svrSystem, localRelPath)
				localFullPath = filepath.Join(targetDir, localRelPath)
			}

			if isDir {
				// Create directory
				return ensureLocalDir(localFullPath)
			}

			// Download file
			currentFile++
			ui.Printf("Downloading file %d/%d: %s\n", currentFile, fileCount, rPath)

			// Open remote file
			rFile, err := ctx.sftpCli.Open(rPath)
			if err != nil {
				return fmt.Errorf("failed to open remote file: %w", err)
			}
			defer func() { _ = rFile.Close() }()

			// Get file size
			fi, sErr := ctx.sftpCli.Stat(rPath)
			if sErr != nil {
				return fmt.Errorf("failed to get remote file info: %w", sErr)
			}
			fileSize := fi.Size()

			// Create local file
			lFile, lErr := os.Create(localFullPath)
			if lErr != nil {
				return fmt.Errorf("failed to create local file: %w", lErr)
			}
			defer func() { _ = lFile.Close() }()

			// Copy file with progress
			bytesWritten, cErr := ctx.copyFileWithProgress(rFile, lFile, rPath, localFullPath, fileSize, fmt.Sprintf("Download (%d/%d)", currentFile, fileCount), ui)
			if cErr != nil {
				return fmt.Errorf("failed to copy file: %w", cErr)
			}
			downloadedSize += bytesWritten
			clearStatus := cursorUp + cursorClear
			ui.Printf("%sDownloaded file %d/%d: %s\n", clearStatus, currentFile, fileCount, rPath)

			return nil
		})

		if wrdErr != nil {
			return fmt.Errorf("error during download: %w", wrdErr)
		}

		ui.Printf("Downloaded directory %s to %s (%d files, %.2f MB)\n",
			remotePath,
			localPath,
			fileCount,
			float64(downloadedSize)/(1024*1024))
	} else {
		// Single file download
		localFilePath := filepath.Join(
			localPath,
			// Format path to local format
			spath.FromToSlash(
				ctx.svrSystem,
				// Basedir from remote format
				spath.Base(ctx.cliSystem, remotePath)))

		ui.Printf("Downloading file %s to %s (%.2f KB)\n", remotePath, localFilePath, float64(rpFi.Size())/1024.0)

		// Open remote file
		rFile, rErr := ctx.sftpCli.Open(remotePath)
		if rErr != nil {
			return fmt.Errorf("failed to open remote file: %w", rErr)
		}
		defer func() { _ = rFile.Close() }()

		// Create local file
		lFile, cErr := os.Create(localFilePath)
		if cErr != nil {
			return fmt.Errorf("failed to create local file: %w", cErr)
		}
		defer func() { _ = lFile.Close() }()

		// Copy file with progress
		_, cpErr := ctx.copyFileWithProgress(rFile, lFile, remotePath, localFilePath, rpFi.Size(), "Download", ui)
		if cpErr != nil {
			return fmt.Errorf("failed to download file: %w", cpErr)
		}
	}

	return nil
}
