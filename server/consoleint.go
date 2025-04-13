package server

import (
	"errors"
	"fmt"
	"github.com/pkg/sftp"
	"os"
	"path/filepath"
	"slices"
	"slider/pkg/sflag"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
)

type intConsole struct {
	console   Console
	cliSystem string
}

type sftpCommandRequest struct {
	sftpCli    *sftp.Client
	remoteCwd  *string
	args       []string
	cliHomeDir string
	*intConsole
}

// newSftpConsole provides an interactive SFTP session
func (s *server) newSftpConsole(session *Session, sftpClient *sftp.Client) {
	// Get current remote directory for prompt
	remoteCwd, cErr := sftpClient.Getwd()
	if cErr != nil {
		remoteCwd = ""
		s.console.PrintlnErrorStep("Unable to determine remote directory: %v", cErr)
	}

	// Set Client Info
	cliHomeDir := session.clientInterpreter.HomeDir
	if session.clientInterpreter.System == "windows" {
		cliHomeDir = fmt.Sprintf("/%s", strings.Replace(cliHomeDir, "\\", "/", -1))
	}
	cliUser := strings.ToLower(session.clientInterpreter.User)
	cliHostname := strings.ToLower(session.clientInterpreter.Hostname)
	cliSystem := strings.ToLower(session.clientInterpreter.System)

	// New console
	ic := &intConsole{
		console:   s.console,
		cliSystem: cliSystem,
	}

	// Define SFTP prompt
	sftpPrompt := func() string {
		rCwd := remoteCwd
		if strings.HasPrefix(remoteCwd, cliHomeDir) {
			rCwd = strings.Replace(remoteCwd, cliHomeDir, "~", 1)
		}

		return fmt.Sprintf(
			"\r(%sS%d%s) %s@%s:%s%s>%s ",
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

	for {
		input, rErr := s.console.Term.ReadLine()
		if rErr != nil {
			s.console.PrintlnErrorStep("Error reading command: %v", rErr)
			break
		}

		// Split the command into parts
		cmdParts := make([]string, 0)
		cmdParts = append(cmdParts, strings.Fields(input)...)

		if cmdParts[0] == "" {
			continue
		}
		command := strings.ToLower(cmdParts[0])
		args := cmdParts[1:]

		// Process commands
		switch command {
		case helpCmd:
			ic.printSftpConsoleHelp()
		case "pwd", "getwd":
			if len(args) > 0 {
				s.console.PrintlnErrorStep("Too many arguments\n")
				return
			}
			s.console.TermPrintf("%s\n\n", remoteCwd)
		case "exit", "quit":
			// Exit SFTP session
			return
		case "shell":
			s.shellCommand("-s", fmt.Sprintf("%d", session.sessionID), "-i")
		default:
			cmdIndex, cmdErr := ic.isCommand(command)
			if cmdErr != nil {
				s.console.PrintlnErrorStep("%v\n", cmdErr)
				continue
			}
			cmdReq := &sftpCommandRequest{
				sftpCli:    sftpClient,
				remoteCwd:  &remoteCwd,
				args:       args,
				cliHomeDir: cliHomeDir,
				intConsole: ic,
			}
			commands[cmdIndex].cmdFunc(cmdReq)
			s.console.Term.SetPrompt(sftpPrompt())
			s.console.Println("")
		}
	}
}

func (ic *intConsole) isCommand(command string) (string, error) {
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
		for _, a := range commands[k].alias {
			cmdList = append(cmdList, a)
		}

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

func (ic *intConsole) commandSftpList(c *sftpCommandRequest) {
	path := *c.remoteCwd

	if len(c.args) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
	}

	if len(c.args) == 1 {
		path = c.args[0]
	}

	// If path is relative, join with current directory
	if !filepath.IsAbs(path) && path != "." {
		path = filepath.Join(*c.remoteCwd, path)
	}
	entries, err := c.sftpCli.ReadDir(path)
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
			target, lErr := c.sftpCli.ReadLink(entry.Name())
			if lErr == nil {
				tI, tErr := c.sftpCli.Stat(target)
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

		var uid, gid string
		if ic.cliSystem != "windows" {
			uid = fmt.Sprintf("%d", entry.Sys().(*sftp.FileStat).UID)
			gid = fmt.Sprintf("%d", entry.Sys().(*sftp.FileStat).GID)
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t\n",
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

func (ic *intConsole) commandSftpCd(c *sftpCommandRequest) {
	if len(c.args) < 1 {
		*c.remoteCwd = c.cliHomeDir
		return
	}
	if len(c.args) > 1 {
		ic.console.PrintlnErrorStep("Too many arguments")
		return
	}

	// Handle special paths
	newPath := c.args[0]
	// Handle "." (current directory) - no change needed
	if newPath == "." {
		return
	}

	// Handle ".." (parent directory)
	if newPath == ".." {
		// Get parent directory
		parentPath := filepath.Dir(*c.remoteCwd)
		if parentPath == *c.remoteCwd {
			// Already at root
			return
		}
		newPath = parentPath
	} else if !filepath.IsAbs(newPath) {
		// Relative path, join with current directory
		newPath = filepath.Join(*c.remoteCwd, newPath)
	}

	// Check if directory exists and is accessible
	fi, err := c.sftpCli.Stat(newPath)
	if err != nil {
		ic.console.PrintlnErrorStep("Failed to stat \"%s\": %v", newPath, err)
		return
	}

	if !fi.IsDir() {
		ic.console.PrintlnErrorStep("Not a directory: %s", newPath)
		return
	}

	// Update the current directory
	*c.remoteCwd = newPath
}

func (ic *intConsole) commandSftpMkdir(c *sftpCommandRequest) {
	mkdirFlags := sflag.NewFlagPack([]string{mkdCmd}, mkdUsage, mkdDesc, ic.console.Term)
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
	dirPath := flagArgs[0]

	// Process directory path
	if !filepath.IsAbs(dirPath) {
		dirPath = filepath.Join(*c.remoteCwd, dirPath)
	}

	// Check if the directory already exists
	_, err := c.sftpCli.Stat(dirPath)
	if err == nil {
		ic.console.PrintlnErrorStep("directory or file already exists: %s", dirPath)
		return
	}

	// Create the directory
	err = c.sftpCli.Mkdir(dirPath)
	if err != nil {
		ic.console.PrintlnErrorStep("failed to create directory: %v", err)
		return
	}

	ic.console.PrintlnOkStep("Created directory: %s", dirPath)
}

func (ic *intConsole) commandSftpRm(c *sftpCommandRequest) {
	rmFlags := sflag.NewFlagPack(ic.initSftpCommands()[rmCmd].alias, rmUsage, rmDesc, ic.console.Term)
	recursive, _ := rmFlags.NewBoolFlag("r", "", "Remove directory and their contents recursively", false)
	rmFlags.Set.Usage = func() {
		rmFlags.PrintUsage(true)
	}

	if pErr := rmFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := rmFlags.Set.Args()
	if len(flagArgs) != 1 {
		rmFlags.PrintUsage(true)
		return
	}

	// Process path
	path := flagArgs[0]

	if !filepath.IsAbs(path) {
		path = filepath.Join(*c.remoteCwd, path)
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

func (ic *intConsole) commandSftpGet(c *sftpCommandRequest) {
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

	// Process remote file path
	remotePath := flagArgs[0]

	// Determine local path
	localPath := filepath.Base(remotePath)
	if len(flagArgs) > 1 {
		localPath = flagArgs[1]
	}

	if !filepath.IsAbs(remotePath) {
		remotePath = filepath.Join(*c.remoteCwd, remotePath)
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

		// Create base directory
		ldErr := ensureLocalDir(localPath)
		if ldErr != nil {
			ic.console.TermPrintf("Failed to create local directory: %v\n", ldErr)
			return
		}

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

		wrdErr := ic.walkRemoteDir(c.sftpCli, remotePath, "", func(remotePath, localRelPath string, isDir bool) error {
			localFullPath := filepath.Join(localPath, localRelPath)

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
		// Single file download
		ic.console.TermPrintf("Downloading file %s to %s (%.2f KB)\n", remotePath, localPath, float64(rpFi.Size())/1024.0)

		// Open remote file
		rFile, rErr := c.sftpCli.Open(remotePath)
		if rErr != nil {
			ic.console.PrintlnErrorStep("Failed to open remote file: %v", rErr)
			return
		}
		defer func() { _ = rFile.Close() }()

		// Create local file
		lFile, cErr := os.Create(localPath)
		if cErr != nil {
			ic.console.PrintlnErrorStep("Failed to create local file: %v", cErr)
			return
		}
		defer func() { _ = lFile.Close() }()

		// Copy file with progress
		_, cpErr := ic.copyFileWithProgress(rFile, lFile, remotePath, localPath, rpFi.Size(), "Download")
		if cpErr != nil {
			ic.console.PrintlnErrorStep("Failed to download file: %v", cpErr)
		}
	}
}

func (ic *intConsole) commandSftpPut(c *sftpCommandRequest) {
	putFlags := sflag.NewFlagPack(ic.initSftpCommands()[putCmd].alias, putUsage, putDesc, ic.console.Term)
	recursive, _ := putFlags.NewBoolFlag("r", "", "Upload directory recursively", false)
	putFlags.Set.Usage = func() {
		putFlags.PrintUsage(true)
	}

	if pErr := putFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := putFlags.Set.Args()
	if len(flagArgs) != 1 {
		putFlags.PrintUsage(true)
		return
	}

	// Process local path
	localPath := flagArgs[0]

	// Get local file info to check if it exists
	localFileInfo, lsErr := os.Stat(localPath)
	if lsErr != nil {
		ic.console.PrintlnErrorStep("Failed to access local path \"%s\"", localPath)
		return
	}

	// Determine remote path
	remotePath := filepath.Base(localPath)
	if len(flagArgs) > 1 {
		remotePath = flagArgs[1]
	}

	// If remote path is not absolute, join with current working directory
	if !filepath.IsAbs(remotePath) {
		remotePath = filepath.Join(*c.remoteCwd, remotePath)
	}

	// Handle differently based on whether it's a directory or file
	if localFileInfo.IsDir() {
		if !*recursive {
			ic.console.PrintlnErrorStep("Cannot upload a directory without -r flag")
			return
		}

		// Recursive directory upload
		ic.console.TermPrintf("Uploading directory %s to %s", localPath, remotePath)

		// Create base directory on remote
		erErr := ensureRemoteDir(c.sftpCli, remotePath)
		if erErr != nil {
			ic.console.PrintlnErrorStep("Failed to create remote directory: %v", erErr)
			return
		}

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

		wl2Err := ic.walkLocalDir(localPath, "", func(localPath, remoteRelPath string, isDir bool) error {
			remoteFullPath := filepath.Join(remotePath, remoteRelPath)

			if isDir {
				// Create directory
				return ensureRemoteDir(c.sftpCli, remoteFullPath)
			} else {
				// Upload file
				currentFile++
				ic.console.TermPrintf("Uploading file %d/%d: %s", currentFile, fileCount, localPath)

				// Open local file
				lFile, err := os.Open(localPath)
				if err != nil {
					return fmt.Errorf("failed to open local file: %v", err)
				}
				defer func() { _ = lFile.Close() }()

				// Get file size
				fi, lsErr := os.Stat(localPath)
				if lsErr != nil {
					return fmt.Errorf("failed to get local file info: %v", lsErr)
				}
				fileSize := fi.Size()

				// Create remote file
				rFile, cErr := c.sftpCli.Create(remoteFullPath)
				if cErr != nil {
					return fmt.Errorf("failed to create remote file: %v", cErr)
				}
				defer func() { _ = rFile.Close() }()

				// Copy file with progress
				bytesWritten, cpErr := ic.copyFileWithProgress(lFile, rFile, localPath, remoteFullPath, fileSize, fmt.Sprintf("Upload (%d/%d)", currentFile, fileCount))
				if err != nil {
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
			ic.console.PrintlnErrorStep("Failed to create remote file \"%s\": %v", localPath, cErr)
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

func (ic *intConsole) commandSftpChmod(c *sftpCommandRequest) {
	chmodFlags := sflag.NewFlagPack(ic.initSftpCommands()[chmodCmd].alias, chmodUsage, chmodDesc, ic.console.Term)
	chmodFlags.Set.Usage = func() {
		chmodFlags.PrintUsage(true)
	}

	if pErr := chmodFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := chmodFlags.Set.Args()
	if len(flagArgs) != 2 {
		chmodFlags.PrintUsage(true)
		return
	}

	// Parse permissions
	modeStr := flagArgs[0]
	path := flagArgs[1]

	// Handle relative path
	if !filepath.IsAbs(path) {
		path = filepath.Join(*c.remoteCwd, path)
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

func (ic *intConsole) commandSftpStat(c *sftpCommandRequest) {
	statFlags := sflag.NewFlagPack(ic.initSftpCommands()[statCmd].alias, statUsage, statDesc, ic.console.Term)
	statFlags.Set.Usage = func() {
		statFlags.PrintUsage(true)
	}

	if pErr := statFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := statFlags.Set.Args()
	if len(flagArgs) != 1 {
		statFlags.PrintUsage(true)
		return
	}

	path := flagArgs[0]
	if !filepath.IsAbs(path) {
		path = filepath.Join(*c.remoteCwd, path)
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

func (ic *intConsole) commandSftpMove(c *sftpCommandRequest) {
	mvFlags := sflag.NewFlagPack(ic.initSftpCommands()[mvCmd].alias, mvUsage, mvDesc, ic.console.Term)
	mvFlags.Set.Usage = func() {
		mvFlags.PrintUsage(true)
	}

	if pErr := mvFlags.Set.Parse(c.args); pErr != nil {
		return
	}

	flagArgs := mvFlags.Set.Args()
	if len(flagArgs) != 2 {
		mvFlags.PrintUsage(true)
		return
	}

	// Process paths
	srcPath := flagArgs[0]
	dstPath := flagArgs[1]

	// Handle relative paths
	if !filepath.IsAbs(srcPath) {
		srcPath = filepath.Join(*c.remoteCwd, srcPath)
	}
	if !filepath.IsAbs(dstPath) {
		dstPath = filepath.Join(*c.remoteCwd, dstPath)
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
