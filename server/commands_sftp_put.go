package server

import (
	"errors"
	"fmt"
	"os"
	"slider/pkg/conf"
	"slider/pkg/escseq"
	"slider/pkg/spath"

	"github.com/spf13/pflag"
)

const (
	putCmd   = "put"
	putDesc  = "Upload file or directory to remote"
	putUsage = "put [-r] <local_path>"
)

// SftpPutCommand implements the 'put' command for uploading files
type SftpPutCommand struct{}

func (c *SftpPutCommand) Name() string             { return putCmd }
func (c *SftpPutCommand) Description() string      { return putDesc }
func (c *SftpPutCommand) Usage() string            { return putUsage }
func (c *SftpPutCommand) IsRemote() bool           { return true }
func (c *SftpPutCommand) IsRemoteCompletion() bool { return false }

func (c *SftpPutCommand) Run(execCtx *ExecutionContext, args []string) error {
	sftpCtx := execCtx.sftpCtx
	if sftpCtx == nil {
		return fmt.Errorf("SFTP context not initialized")
	}
	ui := execCtx.UI()

	putFlags := pflag.NewFlagSet(putCmd, pflag.ContinueOnError)
	putFlags.SetOutput(ui.Writer())

	recursive := putFlags.BoolP("recursive", "r", false, "Upload directories recursively")

	putFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", putUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", putDesc)
		putFlags.PrintDefaults()
	}

	if pErr := putFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		return pErr
	}

	// Validate exact args
	if putFlags.NArg() != 1 {
		return fmt.Errorf("exactly 1 argument required, got %d", putFlags.NArg())
	}

	localPath := putFlags.Args()[0]

	if !spath.IsAbs(sftpCtx.LocalSystem(), localPath) {
		localPath = spath.Join(sftpCtx.LocalSystem(), []string{sftpCtx.GetLocalCwd(), localPath})
	}

	// Get local file info to check if it exists
	localFileInfo, lsErr := os.Stat(localPath)
	if lsErr != nil {
		return fmt.Errorf("failed to access local path: %w", lsErr)
	}

	// Get basename of the local path for remote destination
	baseName := spath.Base(sftpCtx.LocalSystem(), localPath)
	// Ensure paths correspond to the target system
	baseName = spath.FromToSlash(sftpCtx.RemoteSystem(), baseName)
	// Construct the remote path using the basename and current remote directory
	remotePath := spath.Join(sftpCtx.RemoteSystem(), []string{sftpCtx.GetRemoteCwd(), baseName})

	// Handle differently based on whether it's a directory or file
	if localFileInfo.IsDir() {
		if !*recursive {
			return fmt.Errorf("cannot upload a directory without \"-r\" flag")
		}

		// Recursive directory upload
		ui.Printf("Uploading directory %s to %s\n", localPath, remotePath)

		// Count files for progress reporting
		fileCount := 0
		totalSize := int64(0)

		// First pass: count files and total size
		wl1Err := sftpCtx.walkLocalDir(localPath, "", func(lPath, remoteRelPath string, isDir bool) error {
			if !isDir {
				fileCount++
				fi, err := os.Stat(lPath)
				if err != nil {
					return err
				}
				totalSize += fi.Size()
			}
			return nil
		})

		if wl1Err != nil {
			return fmt.Errorf("failed to scan directory: %w", wl1Err)
		}

		ui.Printf("Found %d files totaling %.2f MB\n", fileCount, float64(totalSize)/(1024*1024))

		// Second pass: upload files
		currentFile := 0
		uploadedSize := int64(0)

		// Create the target directory for the upload
		if err := ensureRemoteDir(sftpCtx.sftpCli, remotePath); err != nil {
			return fmt.Errorf("failed to create target directory: %w", err)
		}

		wl2Err := sftpCtx.walkLocalDir(localPath, "", func(lPath, remoteRelPath string, isDir bool) error {
			var remoteFullPath string
			if remoteRelPath == "" {
				remoteFullPath = remotePath
			} else {
				// Use appropriate path for the remote OS
				remoteRelPath = spath.FromToSlash(sftpCtx.RemoteSystem(), remoteRelPath)
				remoteFullPath = spath.Join(sftpCtx.RemoteSystem(), []string{remotePath, remoteRelPath})
			}

			if isDir {
				// Create directory
				return ensureRemoteDir(sftpCtx.sftpCli, remoteFullPath)
			}

			// Upload file
			currentFile++
			ui.Printf("Uploading file %d/%d: %s\n", currentFile, fileCount, lPath)

			// Open local file
			lFile, err := os.Open(lPath)
			if err != nil {
				return fmt.Errorf("failed to open local file: %w", err)
			}
			defer func() { _ = lFile.Close() }()

			// Get file size
			fi, sErr := os.Stat(lPath)
			if sErr != nil {
				return fmt.Errorf("failed to get local file info: %w", sErr)
			}
			fileSize := fi.Size()

			// Create remote file
			rFile, rErr := sftpCtx.sftpCli.Create(remoteFullPath)
			if rErr != nil {
				return fmt.Errorf("failed to create remote file: %w", rErr)
			}
			defer func() { _ = rFile.Close() }()

			// Copy file with progress
			bytesWritten, cErr := sftpCtx.copyFileWithProgress(lFile, rFile, fileSize, fmt.Sprintf("Upload (%d/%d)", currentFile, fileCount), ui)
			if cErr != nil {
				return fmt.Errorf("failed to copy file: %w", cErr)
			}

			uploadedSize += bytesWritten
			clearStatus := escseq.CursorUp() + escseq.CursorClear()
			ui.Printf("%sUploaded file %d/%d: %s\n", clearStatus, currentFile, fileCount, lPath)

			return nil
		})

		if wl2Err != nil {
			return fmt.Errorf("error during upload: %w", wl2Err)
		}

		ui.Printf("Uploaded directory %s to %s (%d files, %.2f MB)\n",
			localPath,
			remotePath,
			fileCount,
			float64(uploadedSize)/conf.BytesPerMB)
	} else {
		// Single file upload
		ui.Printf("Uploading file %s to %s (%.2f KB)\n", localPath, remotePath, float64(localFileInfo.Size())/1024.0)

		// Open local file
		lFile, lErr := os.Open(localPath)
		if lErr != nil {
			return fmt.Errorf("failed to open local file: %w", lErr)
		}
		defer func() { _ = lFile.Close() }()

		// Create remote file
		rFile, rErr := sftpCtx.sftpCli.Create(remotePath)
		if rErr != nil {
			return fmt.Errorf("failed to create remote file: %w", rErr)
		}
		defer func() { _ = rFile.Close() }()

		// Copy file with progress
		bytesWritten, cpErr := sftpCtx.copyFileWithProgress(lFile, rFile, localFileInfo.Size(), "Upload", ui)
		if cpErr != nil {
			return fmt.Errorf("failed to upload file: %w", cpErr)
		}

		clearStatus := escseq.CursorUp() + escseq.CursorClear()
		ui.Printf("%sUploaded file: %s (%.2f MB)\n", clearStatus, localPath, float64(bytesWritten)/conf.BytesPerMB)
	}

	return nil
}
