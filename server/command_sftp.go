package server

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slider/pkg/spath"

	"github.com/pkg/sftp"
)

// SftpCommandContext provides SFTP-specific context for commands
type SftpCommandContext struct {
	sftpCli    *sftp.Client
	session    *Session
	remoteCwd  *string
	localCwd   *string
	cliSystem  string
	svrSystem  string
	cliHomeDir string
	srvHomeDir string
}

// SftpCommand extends the Command interface with SFTP-specific context
type SftpCommand interface {
	Command
	// IsRemote returns true if this command operates on a remote filesystem
	IsRemote() bool
}

// initSftpRegistry initializes the SFTP command registry
func (s *server) initSftpRegistry(session *Session, sftpClient *sftp.Client, remoteCwd, localCwd *string) {
	s.sftpCommandRegistry = NewCommandRegistry()

	// Initialize SFTP context
	s.sftpContext = &SftpCommandContext{
		sftpCli:    sftpClient,
		session:    session,
		remoteCwd:  remoteCwd,
		localCwd:   localCwd,
		cliSystem:  session.clientInterpreter.System,
		svrSystem:  s.serverInterpreter.System,
		cliHomeDir: session.clientInterpreter.HomeDir,
		srvHomeDir: s.serverInterpreter.HomeDir,
	}

	// Register basic commands
	s.sftpCommandRegistry.Register(&SftpHelpCommand{})
	s.sftpCommandRegistry.Register(&SftpExitCommand{})

	// Register pwd commands
	s.sftpCommandRegistry.Register(&SftpPwdCommand{isRemote: true})
	s.sftpCommandRegistry.RegisterAlias("getwd", pwdCmd)
	s.sftpCommandRegistry.Register(&SftpPwdCommand{isRemote: false})
	s.sftpCommandRegistry.RegisterAlias("lgetwd", lPwdCmd)

	// Register cd commands
	s.sftpCommandRegistry.Register(&SftpCdCommand{isRemote: true})
	s.sftpCommandRegistry.RegisterAlias("chdir", cdCmd)
	s.sftpCommandRegistry.Register(&SftpCdCommand{isRemote: false})

	// Register ls commands
	s.sftpCommandRegistry.Register(&SftpLsCommand{isRemote: true})
	s.sftpCommandRegistry.RegisterAlias("dir", lsCmd)
	s.sftpCommandRegistry.RegisterAlias("list", lsCmd)
	s.sftpCommandRegistry.Register(&SftpLsCommand{isRemote: false})
	s.sftpCommandRegistry.RegisterAlias("ldir", lLsCmd)
	s.sftpCommandRegistry.RegisterAlias("llist", lLsCmd)

	// Register mkdir commands
	s.sftpCommandRegistry.Register(&SftpMkdirCommand{isRemote: true})
	s.sftpCommandRegistry.Register(&SftpMkdirCommand{isRemote: false})

	// Register rm command (remote only)
	s.sftpCommandRegistry.Register(&SftpRmCommand{})
	s.sftpCommandRegistry.RegisterAlias("del", rmCmd)
	s.sftpCommandRegistry.RegisterAlias("delete", rmCmd)

	// Register stat command (remote only)
	s.sftpCommandRegistry.Register(&SftpStatCommand{})
	s.sftpCommandRegistry.RegisterAlias("info", statCmd)

	// Register mv command (remote only)
	s.sftpCommandRegistry.Register(&SftpMvCommand{})
	s.sftpCommandRegistry.RegisterAlias("rename", mvCmd)
	s.sftpCommandRegistry.RegisterAlias("move", mvCmd)

	// Register chmod command (remote only, non-Windows)
	if s.sftpContext.cliSystem != "windows" {
		s.sftpCommandRegistry.Register(&SftpChmodCommand{})
	}

	// Register get command
	s.sftpCommandRegistry.Register(&SftpGetCommand{})
	s.sftpCommandRegistry.RegisterAlias("download", getCmd)

	// Register put command
	s.sftpCommandRegistry.Register(&SftpPutCommand{})
	s.sftpCommandRegistry.RegisterAlias("upload", putCmd)
}

func (ctx *SftpCommandContext) getCwd(isRemote bool) string {
	if isRemote {
		return *ctx.remoteCwd
	}
	return *ctx.localCwd
}

func (ctx *SftpCommandContext) setCwd(path string, isRemote bool) {
	if isRemote {
		*ctx.remoteCwd = path
	} else {
		*ctx.localCwd = path
	}
}

func (ctx *SftpCommandContext) readDir(entryName string, isRemote bool) ([]os.FileInfo, error) {
	var entries []os.FileInfo
	if isRemote {
		de, err := ctx.sftpCli.ReadDir(entryName)
		if err != nil {
			return nil, fmt.Errorf("failed to read directory \"%s\": %v", entryName, err)
		}
		return de, nil
	}
	de, err := os.ReadDir(entryName)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory \"%s\": %v", entryName, err)
	}
	for _, e := range de {
		entry, eErr := e.Info()
		if eErr != nil {
			return nil, fmt.Errorf("failed to read directory content \"%s\": %v", entryName, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (ctx *SftpCommandContext) readLink(entryName string, isRemote bool) (string, error) {
	if isRemote {
		return ctx.sftpCli.ReadLink(entryName)
	}
	return os.Readlink(entryName)
}

func (ctx *SftpCommandContext) pathMkDir(path string, isRemote bool, parents bool) error {
	var err error
	if isRemote {
		if parents {
			err = ctx.sftpCli.MkdirAll(path)
		} else {
			err = ctx.sftpCli.Mkdir(path)
		}
	} else {
		if parents {
			err = os.MkdirAll(path, os.ModePerm)
		} else {
			err = os.Mkdir(path, os.ModePerm)
		}
	}
	return err
}

func (ctx *SftpCommandContext) pathStat(path string, isRemote bool) (os.FileInfo, error) {
	if isRemote {
		return ctx.sftpCli.Stat(path)
	}
	return os.Stat(path)
}

func (ctx *SftpCommandContext) getContextSystem(isRemote bool) string {
	if isRemote {
		return ctx.cliSystem
	}
	// Use default permissions
	return ctx.svrSystem
}

// getFileIdInfo returns the UID and GID of a file or 0 0 if not available
func (ctx *SftpCommandContext) getFileIdInfo(entry os.FileInfo, isRemote bool) (int, int) {
	if isRemote {
		// For remote SFTP files
		if sftpStat, ok := entry.Sys().(*sftp.FileStat); ok {
			return int(sftpStat.UID), int(sftpStat.GID)
		}
	}
	// For local files - this syscall doesn't exist on Windows
	uid, _ := spath.GetFileInfoUid(entry)
	gid, _ := spath.GetFileInfoGid(entry)
	return uid, gid
}

// walkRemoteDir walks a remote directory recursively and calls the callback for each entry
func (ctx *SftpCommandContext) walkRemoteDir(remotePath, relPath string, callback func(remotePath, relPath string, isDir bool) error) error {
	// Call callback for the directory itself if relPath is not empty
	if relPath != "" {
		if err := callback(remotePath, relPath, true); err != nil {
			return err
		}
	}

	// Read directory entries
	entries, err := ctx.sftpCli.ReadDir(remotePath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		entryPath := spath.Join(ctx.cliSystem, []string{remotePath, entry.Name()})
		entryRelPath := entry.Name()
		if relPath != "" {
			entryRelPath = spath.Join(ctx.cliSystem, []string{relPath, entry.Name()})
		}

		if entry.IsDir() {
			// Recursively walk subdirectory
			if err := ctx.walkRemoteDir(entryPath, entryRelPath, callback); err != nil {
				return err
			}
		} else {
			// Call callback for file
			if err := callback(entryPath, entryRelPath, false); err != nil {
				return err
			}
		}
	}

	return nil
}

// copyFileWithProgress copies a file from src to dst with progress reporting
func (ctx *SftpCommandContext) copyFileWithProgress(src io.Reader, dst io.Writer, srcPath, dstPath string, totalSize int64, operation string, ui UserInterface) (int64, error) {
	const bufferSize = 32 * 1024 // 32KB buffer
	buffer := make([]byte, bufferSize)
	var written int64
	var lastReportedMB int64 = -1

	for {
		nr, er := src.Read(buffer)
		if nr > 0 {
			nw, ew := dst.Write(buffer[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = fmt.Errorf("invalid write result")
				}
			}
			written += int64(nw)
			if ew != nil {
				return written, ew
			}
			if nr != nw {
				return written, io.ErrShortWrite
			}

			// Clear previous progress line
			clear := ""
			if lastReportedMB != -1 {
				clear = eraseLine
			}

			// Report progress every 1MB or at completion
			currentMB := written / 1048576
			if currentMB != lastReportedMB || written == totalSize {
				lastReportedMB = currentMB
				progress := float64(written) / float64(totalSize) * 100
				ui.Printf("%s%s: %.1f%% (%.2f MB / %.2f MB)", clear, operation, progress, float64(written)/(1024*1024), float64(totalSize)/(1024*1024))
			}
		}
		if er != nil {
			if er != io.EOF {
				return written, er
			}
			break
		}
	}
	return written, nil
}

// walkLocalDir walks a local directory recursively and calls the callback for each entry
func (ctx *SftpCommandContext) walkLocalDir(localPath, relPath string, callback func(localPath, relPath string, isDir bool) error) error {
	// Call callback for the directory itself if relPath is not empty
	if relPath != "" {
		if err := callback(localPath, relPath, true); err != nil {
			return err
		}
	}

	// Read directory entries
	entries, err := os.ReadDir(localPath)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(localPath, entry.Name())
		entryRelPath := entry.Name()
		if relPath != "" {
			entryRelPath = filepath.Join(relPath, entry.Name())
		}

		if entry.IsDir() {
			// Recursively walk subdirectory
			if err := ctx.walkLocalDir(entryPath, entryRelPath, callback); err != nil {
				return err
			}
		} else {
			// Call callback for file
			if err := callback(entryPath, entryRelPath, false); err != nil {
				return err
			}
		}
	}

	return nil
}
