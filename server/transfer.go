package server

import (
	"fmt"
	"github.com/pkg/sftp"
	"io"
	"os"
	"path/filepath"
	"slider/pkg/spath"
	"strings"
	"time"
)

// progressReader implements an io.Reader that reports progress
type progressReader struct {
	r            io.Reader
	totalRead    int64
	progressChan chan<- int64
}

// Read reads data from the underlying reader and reports progress
func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	pr.totalRead += int64(n)
	pr.progressChan <- pr.totalRead
	return n, err
}

// FileTransferProgress handles progress reporting for file transfers
type FileTransferProgress struct {
	console         Console
	sourceFile      string
	destinationFile string
	fileSize        int64
	start           time.Time
	progressChan    chan int64
	progressDone    chan bool
}

// NewFileTransferProgress creates a new progress reporter for file transfers
func NewFileTransferProgress(console Console, src, dst string, size int64) *FileTransferProgress {
	return &FileTransferProgress{
		console:         console,
		sourceFile:      src,
		destinationFile: dst,
		fileSize:        size,
		start:           time.Now(),
		progressChan:    make(chan int64),
		progressDone:    make(chan bool),
	}
}

// StartReporting begins the progress reporting goroutine
func (ftp *FileTransferProgress) StartReporting(operation string) {
	go func() {
		var lastBytes int64
		var currentBytes int64
		lastTime := ftp.start

		// Create a function to draw the progress bar
		drawProgressBar := func(percent float64, width int) string {
			bar := "["
			completed := int(percent * float64(width) / 100.0)
			for i := 0; i < width; i++ {
				if i < completed {
					bar += "="
				} else if i == completed {
					bar += ">"
				} else {
					bar += " "
				}
			}
			bar += "]"
			return bar
		}

		for {
			select {
			case currentBytes = <-ftp.progressChan:
				currentTime := time.Now()
				elapsed := currentTime.Sub(lastTime).Seconds()

				// Calculate speed and percentage (only update if at least 0.5 seconds has passed, or it's the first update)
				if elapsed >= 0.5 || lastBytes == 0 {
					bytesPerSec := float64(currentBytes-lastBytes) / elapsed
					percentDone := float64(currentBytes) / float64(ftp.fileSize) * 100.0

					// Format speed for display
					speedStr := ""
					if bytesPerSec < 1024 {
						speedStr = fmt.Sprintf("%.0f B/s", bytesPerSec)
					} else if bytesPerSec < 1024*1024 {
						speedStr = fmt.Sprintf("%.1f KB/s", bytesPerSec/1024.0)
					} else {
						speedStr = fmt.Sprintf("%.1f MB/s", bytesPerSec/(1024.0*1024.0))
					}

					// Draw progress bar (30 chars wide)
					progressBar := drawProgressBar(percentDone, 30)

					// Report progress
					fmt.Printf("\r%s %s %.1f%% (%.1f/%.1f MB) %s    ",
						operation,
						progressBar,
						percentDone,
						float64(currentBytes)/(1024.0*1024.0),
						float64(ftp.fileSize)/(1024.0*1024.0),
						speedStr)

					lastTime = currentTime
					lastBytes = currentBytes
				}
			case <-ftp.progressDone:
				// Clear the progress line and print final message
				fmt.Print("\r" + strings.Repeat(" ", 80) + "\r")
				return
			}
		}
	}()
}

// Update sends a progress update
func (ftp *FileTransferProgress) Update(bytesTransferred int64) {
	ftp.progressChan <- bytesTransferred
}

// Finish completes the progress reporting and returns statistics
func (ftp *FileTransferProgress) Finish(bytesTransferred int64) (elapsed float64, speed float64) {
	ftp.progressDone <- true
	elapsed = time.Since(ftp.start).Seconds()
	speed = float64(bytesTransferred) / elapsed / 1024.0 // KB/s
	return elapsed, speed
}

// CopyWithProgress performs an io.Copy operation with progress reporting
func CopyWithProgress(dst io.Writer, src io.Reader, console Console, srcName, dstName string, size int64, operation string) (int64, error) {
	// Create progress tracker
	progress := NewFileTransferProgress(console, srcName, dstName, size)

	// Create progress reader
	var progReader io.Reader
	var bytesCopied int64
	var err error

	// Start progress reporting
	progress.StartReporting(operation)

	// Create appropriate progress wrapper based on which side needs updating
	if dst == nil {
		// We're reading only (e.g., for calculating a hash)
		progReader = &progressReader{
			r:            src,
			totalRead:    0,
			progressChan: progress.progressChan,
		}
		bytesCopied, err = io.Copy(io.Discard, progReader)
	} else if src == nil {
		// We're writing only (unlikely case, but for completeness)
		return 0, fmt.Errorf("source cannot be nil")
	} else {
		// Normal copy case
		progReader = &progressReader{
			r:            src,
			totalRead:    0,
			progressChan: progress.progressChan,
		}
		bytesCopied, err = io.Copy(dst, progReader)
	}

	// Finish progress reporting
	elapsed, speed := progress.Finish(bytesCopied)

	// Log completion
	if err == nil {
		console.PrintlnOkStep("%s complete: %s to %s (%.1f MB) in %.1f seconds (%.1f KB/s)",
			operation,
			srcName,
			dstName,
			float64(bytesCopied)/(1024.0*1024.0),
			elapsed,
			speed)
	}

	return bytesCopied, err
}

// removeDirectoryRecursive recursively removes a directory and its contents
func (ic *sftpConsole) removeDirectoryRecursive(client *sftp.Client, dirPath string) error {
	// List directory contents
	// List directory contents
	entries, err := client.ReadDir(dirPath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %v", err)
	}

	// Process each item in the directory
	for _, entry := range entries {
		path := filepath.Join(dirPath, entry.Name())

		if entry.IsDir() {
			// Recursively remove subdirectory
			err = ic.removeDirectoryRecursive(client, path)
			if err != nil {
				return err
			}
		} else {
			// Remove file
			err = client.Remove(path)
			if err != nil {
				return fmt.Errorf("failed to remove file '%s': %v", path, err)
			}
		}
	}

	// Remove the now empty directory
	err = client.RemoveDirectory(dirPath)
	if err != nil {
		return fmt.Errorf("failed to remove directory '%s': %v", dirPath, err)
	}

	return nil
}

// walkLocalDir recursively walks a local directory for upload operations
func (ic *sftpConsole) walkLocalDir(basePath, relativePath string, callback func(localPath, remotePath string, isDir bool) error) error {
	fullPath := filepath.Join(basePath, relativePath)

	// Get file info
	fileInfo, sErr := os.Stat(fullPath)
	if sErr != nil {
		return fmt.Errorf("failed to access path %s: %v", fullPath, sErr)
	}

	// Calculate the remote path (preserve directory structure)
	remotePath := relativePath
	if remotePath == "" {
		remotePath = filepath.Base(basePath)
	}

	// Process the current item
	cErr := callback(fullPath, remotePath, fileInfo.IsDir())
	if cErr != nil {
		return cErr
	}

	// If it's a directory, process its contents
	if fileInfo.IsDir() {
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read directory %s: %v", fullPath, err)
		}

		for _, entry := range entries {
			entryRelPath := filepath.Join(relativePath, entry.Name())
			err = ic.walkLocalDir(basePath, entryRelPath, callback)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// walkRemoteDir recursively walks a remote directory via SFTP for download operations
func (ic *sftpConsole) walkRemoteDir(sftpClient *sftp.Client, basePath, relativePath string, callback func(remotePath, localPath string, isDir bool) error) error {
	fullPath := filepath.Join(basePath, relativePath)
	if ic.cliSystem != ic.svrSystem {
		fullPath = spath.Join(ic.cliSystem, []string{basePath, relativePath})
	}
	// Get file info
	fileInfo, sErr := sftpClient.Stat(fullPath)
	if sErr != nil {
		return fmt.Errorf("failed to access remote path %s: %v", fullPath, sErr)
	}

	// Calculate the local path (preserve directory structure)
	localPath := relativePath
	if localPath == "" {
		localPath = filepath.Base(basePath)
	}

	// Process the current item
	cbErr := callback(fullPath, localPath, fileInfo.IsDir())
	if cbErr != nil {
		return cbErr
	}

	// If it's a directory, process its contents
	if fileInfo.IsDir() {
		entries, rdErr := sftpClient.ReadDir(fullPath)
		if rdErr != nil {
			return fmt.Errorf("failed to read remote directory %s: %v", fullPath, rdErr)
		}

		for _, entry := range entries {
			entryRelPath := filepath.Join(relativePath, entry.Name())
			wdErr := ic.walkRemoteDir(sftpClient, basePath, entryRelPath, callback)
			if wdErr != nil {
				return wdErr
			}
		}
	}

	return nil
}

// ensureLocalDir ensures a local directory exists for download operations
func ensureLocalDir(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0755)
	}
	return nil
}

// ensureRemoteDir ensures a remote directory exists via SFTP for upload operations
func ensureRemoteDir(sftpClient *sftp.Client, path string) error {
	if _, err := sftpClient.Stat(path); err != nil {
		// Try to create the directory
		return sftpClient.MkdirAll(path)
	}
	return nil
}

// copyFileWithProgress copies a file with progress reporting
func (ic *sftpConsole) copyFileWithProgress(src io.Reader, dst io.Writer, srcName, dstName string, size int64, operation string) (int64, error) {
	return CopyWithProgress(dst, src, ic.console, srcName, dstName, size, operation)
}
