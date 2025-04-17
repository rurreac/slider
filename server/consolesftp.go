package server

import (
	"errors"
	"fmt"
	"github.com/pkg/sftp"
	"os"
	"path/filepath"
	"slices"
	"slider/pkg/sflag"
	"slider/pkg/spath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

type sftpConsole struct {
	console    Console
	cliSystem  string
	svrSystem  string
	cliHomeDir string
	srvHomeDir string
	remoteCwd  *string
	localCwd   *string
}

type sftpCommandRequest struct {
	sftpCli  *sftp.Client
	command  string
	args     []string
	isRemote *bool
	*sftpConsole
}

// newSftpConsole provides an interactive SFTP session
func (s *server) newSftpConsole(session *Session, sftpClient *sftp.Client) {
	// Get current directory
	localCwd, clErr := os.Getwd()
	if clErr != nil {
		localCwd = ""
		s.console.PrintlnErrorStep("Unable to determine local directory: %v", clErr)
	}
	// Get current remote directory for prompt
	remoteCwd, crErr := sftpClient.Getwd()
	if crErr != nil {
		remoteCwd = ""
		s.console.PrintlnErrorStep("Unable to determine remote directory: %v", crErr)
	}

	// Set client and server info
	cliHomeDir := session.clientInterpreter.HomeDir
	srvHomeDir := s.serverInterpreter.HomeDir
	cliSystem := strings.ToLower(session.clientInterpreter.System)
	svrSystem := strings.ToLower(s.serverInterpreter.System)

	// Fixing some path inconsistencies between SFTP client and server
	if cliSystem == "windows" && svrSystem != "windows" /*&& !session.clientInterpreter.PtyOn*/ {
		cliHomeDir = fmt.Sprintf("%s", strings.Replace(cliHomeDir, "/", "\\", -1))
		remoteCwd = strings.Replace(strings.TrimPrefix(remoteCwd, "/"), "/", "\\", -1)
	}
	if cliSystem == "windows" && svrSystem == "windows" {
		cliHomeDir = fmt.Sprintf("%s", strings.Replace(cliHomeDir, "\\", "/", -1))
		remoteCwd = strings.TrimPrefix(remoteCwd, "/")
	}
	if cliSystem != "windows" && svrSystem == "windows" {
		remoteCwd = strings.Replace(remoteCwd, "\\", "/", -1)
	}

	cliUser := strings.ToLower(session.clientInterpreter.User)
	cliHostname := strings.ToLower(session.clientInterpreter.Hostname)

	// New console
	ic := &sftpConsole{
		console:    s.console,
		cliSystem:  cliSystem,
		svrSystem:  svrSystem,
		remoteCwd:  &remoteCwd,
		localCwd:   &localCwd,
		cliHomeDir: cliHomeDir,
		srvHomeDir: srvHomeDir,
	}

	// Define SFTP prompt
	sftpPrompt := func() string {
		rCwd := remoteCwd
		if strings.HasPrefix(remoteCwd, cliHomeDir) {
			rCwd = strings.Replace(remoteCwd, cliHomeDir, "~", 1)
		}

		return fmt.Sprintf(
			"\r(%sS%d%s) %s@%s:%s%s$%s ",
			cyanBold,
			session.sessionID,
			resetColor,
			cliUser,
			cliHostname,
			rCwd,
			cyanBold,
			resetColor,
		)
	}

	// Print welcome message and help info
	s.console.PrintlnDebugStep("Starting interactive session")
	s.console.PrintlnDebugStep("Type \"help\" for available commands, \"exit\" to quit")

	// Set the terminal prompt
	s.console.Term.SetPrompt(sftpPrompt())
	commands := ic.initSftpCommands()
	s.console.setSftpConsoleAutoComplete(commands)

	var isRemote bool

	for {
		input, rErr := s.console.Term.ReadLine()
		if rErr != nil {
			s.console.PrintlnErrorStep("Error reading command: %v", rErr)
			break
		}

		cmdParts := fieldsWithQuotes(input)

		if len(cmdParts) < 1 {
			continue
		}

		if cmdParts[0] == "" {
			continue
		}
		command := strings.ToLower(cmdParts[0])
		args := cmdParts[1:]

		// Process commands
		switch command {
		case helpCmd:
			ic.printConsoleHelp()
		case "pwd", "getwd":
			if len(args) > 0 {
				s.console.PrintlnErrorStep("Too many arguments")
				return
			}
			s.console.TermPrintf("%s\n\n", remoteCwd)
		case "lpwd", "lgetwd":
			if len(args) > 0 {
				s.console.PrintlnErrorStep("Too many arguments")
				return
			}
			s.console.TermPrintf("%s\n\n", localCwd)
		case "exit", "quit":
			// Exit SFTP session
			return
		case "shell":
			eArgs := []string{"-s", fmt.Sprintf("%d", session.sessionID), "-i"}
			eArgs = append(eArgs)
			s.shellCommand(eArgs...)
		case "execute":
			if len(args) < 1 {
				s.console.PrintlnWarnStep("Nothing to execute\n")
				continue
			}
			eArgs := []string{"-s", fmt.Sprintf("%d", session.sessionID)}
			eArgs = append(eArgs, args...)
			s.executeCommand(eArgs...)
			continue
		default:
			// This is meant to be a command to execute locally
			if strings.HasPrefix(command, "!") {
				if len(command) > 1 {
					fullCommand := []string{strings.TrimPrefix(command, "!")}
					fullCommand = append(fullCommand, args...)
					s.notConsoleCommand(fullCommand)
					continue
				}
			}
			// Look for a regular command and execute
			cmdIndex, cmdErr := ic.isCommand(command)
			if cmdErr != nil {
				s.console.PrintlnErrorStep("%v\n", cmdErr)
				continue
			}
			isRemote = commands[cmdIndex].isRemote
			cmdReq := &sftpCommandRequest{
				sftpCli:     sftpClient,
				command:     cmdIndex,
				args:        args,
				isRemote:    &isRemote,
				sftpConsole: ic,
			}
			commands[cmdIndex].cmdFunc(cmdReq)
			s.console.Term.SetPrompt(sftpPrompt())
			s.console.Println("")
		}
	}
}

func fieldsWithQuotes(input string) []string {
	quoted := false
	fields := strings.FieldsFunc(input, func(r rune) bool {
		if r == '"' {
			quoted = true
		}
		return !quoted && r == ' '
	})
	newFields := make([]string, 0)
	for _, item := range fields {
		// Each quoted item must open and close quotes to be considered a field
		nq := strings.Count(item, "\"")
		if nq == 1 {
			newFields = append(newFields, item)
			continue
		}

		if nq%2 == 0 {
			newFields = append(newFields, strings.ReplaceAll(item, "\"", ""))
			continue
		} else {
			newFields = append(newFields, strings.Replace(item, "\"", "", nq/2))
		}

	}
	return newFields
}

func (ic *sftpConsole) isCommand(command string) (string, error) {
	for c, cMap := range ic.initSftpCommands() {
		if slices.Contains(cMap.alias, command) {
			return c, nil
		}
	}
	return "", errors.New("Unknown command: " + command)
}

func (c *Console) setSftpConsoleAutoComplete(commands map[string]sftpCommandStruck) {
	// List of the Ordered the commands for autocompletion
	var cmdList []string
	for k := range commands {
		cmdList = append(cmdList, commands[k].alias...)
	}
	slices.Sort(cmdList)
	// Simple autocompletion
	c.Term.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		// If TAB key is pressed and text was written
		if key == 9 && len(line) > 0 {
			newLine, newPos := autocompleteCommand(line, cmdList)
			return newLine, newPos, true
		}
		return line, pos, false
	}
}

func (c *sftpCommandRequest) readLink(entryName string) (string, error) {
	if *c.isRemote {
		return c.sftpCli.ReadLink(entryName)
	}
	return os.Readlink(entryName)
}

func (c *sftpCommandRequest) readDir(entryName string) ([]os.FileInfo, error) {
	var entries []os.FileInfo
	if *c.isRemote {
		de, err := c.sftpCli.ReadDir(entryName)
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

func (ic *sftpConsole) pathIsAbs(path string, remote bool) bool {
	if remote {
		return spath.IsAbs(ic.cliSystem, path)
	}
	return spath.IsAbs(ic.svrSystem, path)
}

func (ic *sftpConsole) pathJoin(elem []string, remote bool) string {
	if remote {
		return spath.Join(ic.cliSystem, elem)
	}
	return spath.Join(ic.svrSystem, elem)
}

func (c *sftpCommandRequest) pathStat(path string) (os.FileInfo, error) {
	if *c.isRemote {
		return c.sftpCli.Stat(path)
	}
	return os.Stat(path)
}

func (c *sftpCommandRequest) getScopedPath() string {
	if *c.isRemote {
		return *c.remoteCwd
	}
	return *c.localCwd
}

func (c *sftpCommandRequest) getPathIdInfo(entry os.FileInfo) (int, int) {
	if *c.isRemote {
		return int(entry.Sys().(*sftp.FileStat).UID), int(entry.Sys().(*sftp.FileStat).GID)
	}
	// This syscall doesn't exist on Windows
	var uid, gid int
	if u, uErr := spath.GetFileInfoUid(entry); uErr == nil {
		uid = u
	}
	if g, gErr := spath.GetFileInfoGid(entry); gErr == nil {
		gid = g
	}

	return uid, gid
}

func (c *sftpCommandRequest) systemHomeDir() {
	if *c.isRemote {
		*c.remoteCwd = c.cliHomeDir
		return
	}
	*c.localCwd = c.srvHomeDir
}

func (c *sftpCommandRequest) getCwd() string {
	if *c.isRemote {
		return *c.remoteCwd
	}
	return *c.localCwd
}

func (c *sftpCommandRequest) updateCwd(path string) {
	if *c.isRemote {
		*c.remoteCwd = path
		return
	}
	*c.localCwd = path
}

func (c *sftpCommandRequest) pathDir(path string) string {
	if *c.isRemote {
		return spath.Dir(c.cliSystem, path)
	}
	return spath.Dir(c.svrSystem, path)
}

func (c *sftpCommandRequest) pathMkDir(path string) error {
	if *c.isRemote {
		return c.sftpCli.Mkdir(path)
	}
	// Use default permissions
	return os.Mkdir(path, os.ModePerm)
}

func (c *sftpCommandRequest) getContextSystem() string {
	if *c.isRemote {
		return c.cliSystem
	}
	// Use default permissions
	return c.svrSystem
}

func (ic *sftpConsole) commandSftpList(c *sftpCommandRequest) {
	path := c.getScopedPath()

	if len(c.args) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	if len(c.args) == 1 {
		path = c.args[0]
	}

	// If path is relative, join with current directory
	if !ic.pathIsAbs(path, *c.isRemote) && path != "." {
		path = ic.pathJoin([]string{c.getScopedPath(), path}, *c.isRemote)
	}

	entries, err := c.readDir(path)
	if err != nil {
		ic.console.PrintlnErrorStep("Failed to list directory \"%s\": %v", path, err)
		return
	}

	if len(entries) == 0 {
		ic.console.PrintlnDebugStep("Directory is empty")
		return
	}

	// Order files in *nix style
	sort.Slice(entries, func(i, j int) bool {
		return strings.ToLower(strings.TrimPrefix(entries[i].Name(), ".")) <
			strings.ToLower(strings.TrimPrefix(entries[j].Name(), "."))
	})

	tw := new(tabwriter.Writer)
	tw.Init(ic.console.Term, 0, 4, 2, ' ', 0)

	for _, entry := range entries {
		var nameField string
		if entry.IsDir() {
			nameField = fmt.Sprintf("%s%s%s", blueBrightBold, entry.Name(), resetColor)
		} else if entry.Mode()&os.ModeSymlink != 0 {
			nameField = fmt.Sprintf("%s%s%s", cyanBold, entry.Name(), resetColor)
			target, lErr := c.readLink(entry.Name())
			if lErr == nil {
				tI, tErr := c.pathStat(target)
				if tErr != nil {
					target = fmt.Sprintf("%s%s%s", redBold, target, resetColor)
				} else {
					if tI.IsDir() {
						target = fmt.Sprintf("%s%s%s", blueBrightBold, target, resetColor)
					}
				}
				nameField = fmt.Sprintf("%s%s%s -> %s", cyanBold, entry.Name(), resetColor, target)
			}

		} else {
			nameField = entry.Name()
		}

		// Format size for better readability
		size := ""
		if entry.IsDir() {
			size = "<DIR>"
		} else {
			bytesSize := entry.Size()
			if bytesSize < 1024 {
				size = fmt.Sprintf("%d B", bytesSize)
			} else if bytesSize < 1024*1024 {
				size = fmt.Sprintf("%.1f KB", float64(bytesSize)/1024)
			} else if bytesSize < 1024*1024*1024 {
				size = fmt.Sprintf("%.1f MB", float64(bytesSize)/(1024*1024))
			} else {
				size = fmt.Sprintf("%.1f GB", float64(bytesSize)/(1024*1024*1024))
			}
		}

		//var uid, gid string
		// Do not output uid, gid on Windows as it is always 0
		if c.getContextSystem() != "windows" {
			uid, gid := c.getPathIdInfo(entry)
			_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t\n",
				entry.Mode().String(),
				uid,
				gid,
				size,
				entry.ModTime().Format("Jan 02 15:04"),
				nameField)
		} else {
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t\n",
				entry.Mode().String(),
				size,
				entry.ModTime().Format("Jan 02 15:04"),
				nameField)
		}

	}
	_ = tw.Flush()
}

func (ic *sftpConsole) commandSftpCd(c *sftpCommandRequest) {
	if len(c.args) < 1 {
		c.systemHomeDir()
		return
	}

	if len(c.args) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	newPath := c.args[0]
	// Handle "." (current directory) - no change needed
	if newPath == "." {
		return
	}

	// Handle ".." (parent directory)
	if newPath == ".." {
		// Get parent directory
		parentPath := c.pathDir(c.getCwd())
		if parentPath == c.getCwd() {
			// Already at root
			return
		}
		newPath = parentPath
	} else if !c.pathIsAbs(newPath, *c.isRemote) {
		// Relative path, join with current directory
		newPath = c.pathJoin([]string{c.getCwd(), newPath}, *c.isRemote)
	}

	// Check if directory exists and is accessible
	fi, err := c.pathStat(newPath)
	if err != nil {
		ic.console.PrintlnErrorStep("Failed to stat \"%s\": %v", newPath, err)
		return
	}

	if !fi.IsDir() {
		ic.console.PrintlnErrorStep("Not a directory: %s", newPath)
		return
	}

	// Update the current directory
	c.updateCwd(newPath)
	// Notify the new path only if "lcd"
	if !*c.isRemote {
		c.console.PrintlnOkStep("Current local path: %s", newPath)
	}
}

func (ic *sftpConsole) commandSftpMkdir(c *sftpCommandRequest) {
	commands := ic.initSftpCommands()
	mkdirFlags := sflag.NewFlagPack(
		[]string{c.command},
		commands[c.command].usage,
		commands[c.command].description,
		ic.console.Term,
	)
	mkdirFlags.Set.Usage = func() {
		mkdirFlags.PrintUsage(true)
	}

	if pErr := mkdirFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := mkdirFlags.Set.Args()
	if len(flagArgs) < 1 {
		mkdirFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	dirPath := flagArgs[0]

	// Process directory path
	if !ic.pathIsAbs(dirPath, *c.isRemote) {
		dirPath = ic.pathJoin([]string{c.getCwd(), dirPath}, *c.isRemote)
	}

	// Check if the directory already exists
	_, err := c.pathStat(dirPath)
	if err == nil {
		ic.console.PrintlnErrorStep("directory or file already exists: %s", dirPath)
		return
	}

	// Create the directory
	err = c.pathMkDir(dirPath)
	if err != nil {
		ic.console.PrintlnErrorStep("failed to create directory: %v", err)
		return
	}

	ic.console.PrintlnOkStep("Created directory: %s", dirPath)
}

func (ic *sftpConsole) commandSftpRm(c *sftpCommandRequest) {
	rmFlags := sflag.NewFlagPack(ic.initSftpCommands()[rmCmd].alias, rmUsage, rmDesc, ic.console.Term)
	recursive, _ := rmFlags.NewBoolFlag("r", "", "Remove directory and their contents recursively", false)
	rmFlags.Set.Usage = func() {
		rmFlags.PrintUsage(true)
	}

	if pErr := rmFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := rmFlags.Set.Args()
	if len(flagArgs) < 1 {
		rmFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	// Process path
	path := flagArgs[0]

	if !spath.IsAbs(ic.cliSystem, path) {
		path = spath.Join(ic.cliSystem, []string{*c.remoteCwd, path})
	}

	// Check if path exists
	fi, sErr := c.sftpCli.Stat(path)
	if sErr != nil {
		ic.console.PrintlnErrorStep("File or directory not found")
		return
	}

	if fi.IsDir() {
		// It's a directory
		if *recursive {
			// Count items for reporting
			fileCount := 0
			dirCount := 0

			// First pass: count files and directories
			wdErr := ic.walkRemoteDir(c.sftpCli, path, "", func(remotePath, localRelPath string, isDir bool) error {
				if isDir {
					dirCount++
				} else {
					fileCount++
				}
				return nil
			})

			if wdErr != nil {
				ic.console.PrintlnErrorStep("Error scanning directory: %v", wdErr)
				return
			}

			// Confirm deletion with user
			ic.console.TermPrintf("Will delete %d files and %d directories. Proceed? (y/N) ", fileCount, dirCount)
			ic.console.Term.SetPrompt("")
			confirmation, rlErr := ic.console.Term.ReadLine()
			if rlErr != nil || strings.ToLower(confirmation) != "y" {
				ic.console.PrintlnDebugStep("Deletion cancelled")
				return
			}

			// Perform recursive removal
			rmErr := ic.removeDirectoryRecursive(c.sftpCli, path)
			if rmErr != nil {
				ic.console.PrintlnErrorStep("Failed to remove directory recursively: %v", rmErr)
				return
			}
			ic.console.PrintlnOkStep("Removed directory %s (%d files, %d directories)", path, fileCount, dirCount)
		} else {
			// Try to remove empty directory
			rdErr := c.sftpCli.RemoveDirectory(path)
			if rdErr != nil {
				ic.console.TermPrintf("Directory remove error (use '-r' flag): %v", rdErr)
				return
			}
			ic.console.PrintlnOkStep("Removed directory: %s", path)
		}
	} else {
		// It's a file
		rmErr := c.sftpCli.Remove(path)
		if rmErr != nil {
			ic.console.PrintlnErrorStep("Failed to remove file: %v", rmErr)
			return
		}
		ic.console.PrintlnOkStep("Removed file: %s", path)
	}
}

func (ic *sftpConsole) commandSftpGet(c *sftpCommandRequest) {
	getFlags := sflag.NewFlagPack(ic.initSftpCommands()[getCmd].alias, getUsage, getDesc, ic.console.Term)
	recursive, _ := getFlags.NewBoolFlag("r", "", "Download directories recursively", false)
	getFlags.Set.Usage = func() {
		getFlags.PrintUsage(true)
	}

	if pErr := getFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := getFlags.Set.Args()
	if len(flagArgs) < 1 {
		getFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	remotePath := flagArgs[0]
	localPath := *c.localCwd

	if !spath.IsAbs(ic.cliSystem, remotePath) {
		remotePath = spath.Join(ic.cliSystem, []string{*c.remoteCwd, remotePath})
	}

	// Get file info to check if it exists
	rpFi, sErr := c.sftpCli.Stat(remotePath)
	if sErr != nil {
		ic.console.PrintlnErrorStep("Failed to access remote path: %v", sErr)
		return
	}

	// Handle differently based on whether it's a directory or file
	if rpFi.IsDir() {
		if !*recursive {
			ic.console.PrintlnErrorStep("Can not download a directory without \"-r\" flag")
			return
		}

		// Recursive directory download
		ic.console.TermPrintf("Downloading directory %s to %s\n", remotePath, localPath)

		// Count files for progress reporting
		fileCount := 0
		totalSize := int64(0)
		processingError := false

		// First pass: count files and total size
		wsErr := ic.walkRemoteDir(c.sftpCli, remotePath, "", func(remotePath, localRelPath string, isDir bool) error {
			if !isDir {
				fileCount++
				fi, err := c.sftpCli.Stat(remotePath)
				if err != nil {
					return err
				}
				totalSize += fi.Size()
			}
			return nil
		})

		if wsErr != nil {
			ic.console.PrintlnErrorStep("Error scanning directory: %v", wsErr)
			return
		}

		ic.console.TermPrintf("Found %d files totaling %.2f MB\n", fileCount, float64(totalSize)/(1024*1024))

		// Second pass: download files
		currentFile := 0
		downloadedSize := int64(0)

		// Create the target directory for the download
		targetDir := spath.Join(ic.svrSystem, []string{localPath, spath.Base(ic.cliSystem, remotePath)})
		if err := ensureLocalDir(targetDir); err != nil {
			ic.console.PrintlnErrorStep("Failed to create target directory: %v", err)
			return
		}

		wrdErr := ic.walkRemoteDir(c.sftpCli, remotePath, "", func(remotePath, localRelPath string, isDir bool) error {
			var localFullPath string
			if localRelPath == "" {
				localFullPath = targetDir
			} else {
				localRelPath = spath.FromToSlash(ic.svrSystem, localRelPath)
				localFullPath = filepath.Join(targetDir, localRelPath)
			}

			if isDir {
				// Create directory
				return ensureLocalDir(localFullPath)
			} else {
				// Download file
				currentFile++
				ic.console.TermPrintf("Downloading file %d/%d: %s", currentFile, fileCount, remotePath)

				// Open remote file
				rFile, err := c.sftpCli.Open(remotePath)
				if err != nil {
					return fmt.Errorf("failed to open remote file: %v", err)
				}
				defer func() { _ = rFile.Close() }()

				// Get file size
				rpFi, sErr = c.sftpCli.Stat(remotePath)
				if err != nil {
					return fmt.Errorf("failed to get remote file info: %v", sErr)
				}
				fileSize := rpFi.Size()

				// Create local file
				lFile, lErr := os.Create(localFullPath)
				if lErr != nil {
					return fmt.Errorf("failed to create local file: %v", lErr)
				}
				defer func() { _ = lFile.Close() }()

				// Copy file with progress
				bytesWritten, cErr := ic.copyFileWithProgress(rFile, lFile, remotePath, localFullPath, fileSize, fmt.Sprintf("Download (%d/%d)", currentFile, fileCount))
				if err != nil {
					return fmt.Errorf("failed to copy file: %v", cErr)
				}

				downloadedSize += bytesWritten
				return nil
			}
		})

		if wrdErr != nil {
			ic.console.PrintlnErrorStep("Error during download: %v", wrdErr)
			processingError = true
		}

		if !processingError {
			ic.console.TermPrintf("Downloaded directory %s to %s (%d files, %.2f MB)\n",
				remotePath,
				localPath,
				fileCount,
				float64(downloadedSize)/(1024*1024))
		}
	} else {
		localFilePath := filepath.Join(
			localPath,
			// Format path to local format
			spath.FromToSlash(
				ic.svrSystem,
				// Basedir from remote format
				spath.Base(ic.cliSystem, remotePath)))

		ic.console.TermPrintf("Downloading file %s to %s (%.2f KB)\n", remotePath, localFilePath, float64(rpFi.Size())/1024.0)

		// Open remote file
		rFile, rErr := c.sftpCli.Open(remotePath)
		if rErr != nil {
			ic.console.PrintlnErrorStep("Failed to open remote file: %v", rErr)
			return
		}
		defer func() { _ = rFile.Close() }()

		// Create local file
		lFile, cErr := os.Create(localFilePath)
		if cErr != nil {
			ic.console.PrintlnErrorStep("Failed to create local file: %v", cErr)
			return
		}
		defer func() { _ = lFile.Close() }()

		// Copy file with progress
		_, cpErr := ic.copyFileWithProgress(rFile, lFile, remotePath, localFilePath, rpFi.Size(), "Download")
		if cpErr != nil {
			ic.console.PrintlnErrorStep("Failed to download file: %v", cpErr)
		}
	}
}

func (ic *sftpConsole) commandSftpPut(c *sftpCommandRequest) {
	putFlags := sflag.NewFlagPack(ic.initSftpCommands()[putCmd].alias, putUsage, putDesc, ic.console.Term)
	recursive, _ := putFlags.NewBoolFlag("r", "", "Upload directory recursively", false)
	putFlags.Set.Usage = func() {
		putFlags.PrintUsage(true)
	}

	if pErr := putFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := putFlags.Set.Args()
	if len(flagArgs) < 1 {
		putFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	// Process local path
	localPath := flagArgs[0]
	if !spath.IsAbs(c.svrSystem, localPath) {
		localPath = spath.Join(c.svrSystem, []string{*c.localCwd, localPath})
	}

	// Get local file info to check if it exists
	localFileInfo, ls1Err := os.Stat(localPath)
	if ls1Err != nil {
		ic.console.PrintlnErrorStep("Failed to access local path \"%s\"", localPath)
		return
	}

	// Get basename of the local path for remote destination
	baseName := spath.Base(ic.svrSystem, localPath)
	// Ensure paths correspond to the target system
	baseName = spath.FromToSlash(ic.cliSystem, baseName)
	// Construct the remote path using the basename and current remote directory
	remotePath := spath.Join(ic.cliSystem, []string{*c.remoteCwd, baseName})

	// Handle differently based on whether it's a directory or file
	if localFileInfo.IsDir() {
		if !*recursive {
			ic.console.PrintlnErrorStep("Cannot upload a directory without -r flag")
			return
		}

		// Recursive directory upload
		ic.console.TermPrintf("Uploading directory %s to %s\n", localPath, remotePath)

		// Count files for progress reporting
		fileCount := 0
		totalSize := int64(0)
		processingError := false

		// First pass: count files and total size
		wl1Err := ic.walkLocalDir(localPath, "", func(localPath, remoteRelPath string, isDir bool) error {
			if !isDir {
				fileCount++
				fi, err := os.Stat(localPath)
				if err != nil {
					return err
				}
				totalSize += fi.Size()
			}
			return nil
		})

		if wl1Err != nil {
			ic.console.PrintlnErrorStep("Error scanning directory: %v", wl1Err)
			return
		}

		ic.console.TermPrintf("Found %d files totaling %.2f MB\n", fileCount, float64(totalSize)/(1024*1024))

		// Second pass: upload files
		currentFile := 0
		uploadedSize := int64(0)

		// Create the target directory for the upload
		if err := ensureRemoteDir(c.sftpCli, remotePath); err != nil {
			ic.console.PrintlnErrorStep("Failed to create target directory: %v", err)
			return
		}

		wl2Err := ic.walkLocalDir(localPath, "", func(localPath, remoteRelPath string, isDir bool) error {
			var remoteFullPath string
			if remoteRelPath == "" {
				remoteFullPath = remotePath
			} else {
				// Use appropriate path for the remote OS
				remoteRelPath = spath.FromToSlash(ic.cliSystem, remoteRelPath)
				remoteFullPath = spath.Join(ic.cliSystem, []string{remotePath, remoteRelPath})
			}

			if isDir {
				return ensureRemoteDir(c.sftpCli, remoteFullPath)
			} else {
				currentFile++
				ic.console.TermPrintf("Uploading file %d/%d: %s", currentFile, fileCount, localPath)

				// Open local file
				lFile, err := os.Open(localPath)
				if err != nil {
					return fmt.Errorf("failed to open local file: %v", err)
				}
				defer func() { _ = lFile.Close() }()

				// Get file size
				fi, ls2Err := os.Stat(localPath)
				if ls2Err != nil {
					return fmt.Errorf("failed to get local file info: %v", ls2Err)
				}
				fileSize := fi.Size()

				// Ensure parent remote directory exists
				remoteDir := spath.Dir(ic.cliSystem, remoteFullPath)

				if rdErr := ensureRemoteDir(c.sftpCli, remoteDir); rdErr != nil {
					return fmt.Errorf("failed to create remote directory: %v", rdErr)
				}

				// Create remote file
				rFile, cErr := c.sftpCli.Create(remoteFullPath)
				if cErr != nil {
					return fmt.Errorf("failed to create remote file: %v", cErr)
				}
				defer func() { _ = rFile.Close() }()

				// Copy file with progress
				bytesWritten, cpErr := ic.copyFileWithProgress(lFile, rFile, localPath, remoteFullPath, fileSize, fmt.Sprintf("Upload (%d/%d)", currentFile, fileCount))
				if cpErr != nil {
					return fmt.Errorf("failed to copy file: %v", cpErr)
				}

				uploadedSize += bytesWritten
				return nil
			}
		})

		if wl2Err != nil {
			ic.console.PrintlnErrorStep("Error during upload: %v", wl2Err)
			processingError = true
		}

		if !processingError {
			ic.console.TermPrintf("Uploaded directory %s to %s (%d files, %.2f MB)\n",
				localPath,
				remotePath,
				fileCount,
				float64(uploadedSize)/(1024*1024))
		}
	} else {
		// Single file upload
		fileSize := localFileInfo.Size()
		ic.console.TermPrintf("Uploading file %s to %s (%.2f KB)", localPath, remotePath, float64(fileSize)/1024.0)

		// Open local file
		lFile, err := os.Open(localPath)
		if err != nil {
			ic.console.PrintlnErrorStep("Failed to open local file \"%s\": %v", localPath, err)
			return
		}
		defer func() { _ = lFile.Close() }()

		// Create remote file
		rFile, cErr := c.sftpCli.Create(remotePath)
		if cErr != nil {
			ic.console.PrintlnErrorStep("Failed to create remote file \"%s\": %v", remotePath, cErr)
			return
		}
		defer func() { _ = rFile.Close() }()

		// Copy file with progress
		_, err = ic.copyFileWithProgress(lFile, rFile, localPath, remotePath, fileSize, "Upload")
		if err != nil {
			ic.console.PrintlnErrorStep("Failed to upload file \"%s\": %v", localPath, err)
		}
	}
}

func (ic *sftpConsole) commandSftpChmod(c *sftpCommandRequest) {
	chmodFlags := sflag.NewFlagPack(ic.initSftpCommands()[chmodCmd].alias, chmodUsage, chmodDesc, ic.console.Term)
	chmodFlags.Set.Usage = func() {
		chmodFlags.PrintUsage(true)
	}

	if pErr := chmodFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := chmodFlags.Set.Args()
	if len(flagArgs) < 2 {
		chmodFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 2 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	// Parse permissions
	modeStr := flagArgs[0]
	path := flagArgs[1]

	// Handle relative path
	if !spath.IsAbs(ic.cliSystem, path) {
		path = spath.Join(ic.cliSystem, []string{*c.remoteCwd, path})
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
		ic.console.PrintlnErrorStep("Invalid permission format (use octal, e.g. 0755): %v", err)
		return
	}

	// Check if file exists
	_, err = c.sftpCli.Stat(path)
	if err != nil {
		ic.console.PrintlnErrorStep("File or directory \"%s\" not found: %v", path, err)
		return
	}

	// Change permissions
	err = c.sftpCli.Chmod(path, os.FileMode(mode))
	if err != nil {
		ic.console.PrintlnErrorStep("Failed to change \"%s\" permissions: %v", path, err)
		return
	}

	ic.console.PrintlnOkStep("Changed permissions of %s to %s (%s)",
		path,
		modeStr,
		os.FileMode(mode).String())
}

func (ic *sftpConsole) commandSftpStat(c *sftpCommandRequest) {
	statFlags := sflag.NewFlagPack(ic.initSftpCommands()[statCmd].alias, statUsage, statDesc, ic.console.Term)
	statFlags.Set.Usage = func() {
		statFlags.PrintUsage(true)
	}

	if pErr := statFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := statFlags.Set.Args()
	if len(flagArgs) < 1 {
		statFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	path := flagArgs[0]
	if !spath.IsAbs(ic.cliSystem, path) {
		path = spath.Join(ic.cliSystem, []string{*c.remoteCwd, path})
	}

	// Get file info
	fi, err := c.sftpCli.Stat(path)
	if err != nil {
		ic.console.PrintlnErrorStep("Failed to get file information: %v", err)
		return
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
	ic.console.PrintlnOkStep("File Information for: %s\n", path)
	tw := new(tabwriter.Writer)
	tw.Init(ic.console.Term, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\tName:\t%s\n", filepath.Base(path))
	_, _ = fmt.Fprintf(tw, "\tType:\t%s\n", fileType)
	_, _ = fmt.Fprintf(tw, "\tSize:\t%s\n", sizeStr)
	_, _ = fmt.Fprintf(tw, "\tPermissions:\t%s (%04o)\n", fi.Mode().String(), fi.Mode().Perm())
	_, _ = fmt.Fprintf(tw, "\tModified:\t%s\n", fi.ModTime().Format("Jan 02, 2006 15:04:05 MST"))

	// Try to get extended information
	if sftpStat, ok := fi.Sys().(*sftp.FileStat); ok && ic.cliSystem != "windows" {
		// If we can access the underlying FileStat struct
		_, _ = fmt.Fprintf(tw, "\tOwner UID:\t%d\n", sftpStat.UID)
		_, _ = fmt.Fprintf(tw, "\tGroup GID:\t%d\n", sftpStat.GID)
	}
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
}

func (ic *sftpConsole) commandSftpMove(c *sftpCommandRequest) {
	mvFlags := sflag.NewFlagPack(ic.initSftpCommands()[mvCmd].alias, mvUsage, mvDesc, ic.console.Term)
	mvFlags.Set.Usage = func() {
		mvFlags.PrintUsage(true)
	}

	if pErr := mvFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := mvFlags.Set.Args()
	if len(flagArgs) < 2 {
		mvFlags.PrintUsage(true)
		return
	}

	if len(flagArgs) > 2 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	// Process paths
	srcPath := flagArgs[0]
	dstPath := flagArgs[1]

	// Handle relative paths
	if !spath.IsAbs(ic.cliSystem, srcPath) {
		srcPath = spath.Join(ic.cliSystem, []string{*c.remoteCwd, srcPath})
	}
	if !spath.IsAbs(ic.cliSystem, dstPath) {
		dstPath = spath.Join(ic.cliSystem, []string{*c.remoteCwd, dstPath})
	}

	// Check if source exists
	srcFi, err := c.sftpCli.Stat(srcPath)
	if err != nil {
		ic.console.PrintlnErrorStep("Source file or directory \"%s\" not found: %v", srcPath, err)
		return
	}

	// Check if destination already exists
	_, err = c.sftpCli.Stat(dstPath)
	if err == nil {
		ic.console.PrintlnErrorStep("Destination already exists, cannot overwrite")
		return
	}

	// Rename file or directory
	err = c.sftpCli.Rename(srcPath, dstPath)
	if err != nil {
		ic.console.PrintlnErrorStep("Failed to rename \"%s\": %v", srcPath, err)
		return
	}

	if srcFi.IsDir() {
		ic.console.PrintlnOkStep("Renamed directory from %s to %s", srcPath, dstPath)
	} else {
		ic.console.PrintlnOkStep("Renamed file from %s to %s", srcPath, dstPath)
	}
}
