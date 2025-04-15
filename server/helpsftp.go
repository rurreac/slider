package server

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

const (
	// List
	lsCmd  = "ls"
	lsDesc = "List remote directory contents"
	// Get directory
	pwdCmd  = "pwd"
	pwdDesc = "Show current remote directory"
	// Change dir
	cdCmd  = "cd"
	cdDesc = "Change remote directory"
	// Download
	getCmd   = "get"
	getDesc  = "Download file or directory"
	getUsage = "Usage: get [-r] <remote_path> [local_path]"
	// Upload
	putCmd   = "put"
	putDesc  = "Upload file or directory"
	putUsage = "Usage: put [-r] <local_path> [remote_path]"
	// Create dir
	mkdCmd   = "mkdir"
	mkdDesc  = "Create remote directory"
	mkdUsage = "Usage: mkdir <directory>"
	// Chmod
	chmodCmd   = "chmod"
	chmodDesc  = "Change file permissions"
	chmodUsage = "Usage: chmod <permissions> <file>"
	// File info
	statCmd   = "stat"
	statDesc  = "Show detailed file information"
	statUsage = "Usage: stat <file_or_directory>"
	// Remove
	rmCmd   = "rm"
	rmDesc  = "Remove file or directory"
	rmUsage = "Usage: rm [-r] <path>"
	// Move
	mvCmd   = "mv"
	mvDesc  = "Rename or move a file or directory"
	mvUsage = "Usage: rename <source> <destination>"

	// Server-side Commands

	// Local List
	lLsCmd  = "lls"
	lLsDesc = "List local directory contents"
	// Change local dir
	lCdCmd  = "lcd"
	lCdDesc = "Change local directory"
	// Get current local directory
	lPwdCmd  = "lpwd"
	lPwdDesc = "Show current local directory"
	// Create dir
	lMkdCmd   = "lmkdir"
	lMkdDesc  = "Create local directory"
	lMkdUsage = "Usage: lmkdir <directory>"
)

type sftpCommandStruck struct {
	alias       []string
	description string
	usage       string
	cmdFunc     func(request *sftpCommandRequest)
	isRemote    bool
}

func (ic *sftpConsole) initSftpCommands() map[string]sftpCommandStruck {
	var commands = map[string]sftpCommandStruck{
		helpCmd: {
			alias:       []string{helpCmd},
			description: helpDesc,
		},
		exitCmd: {
			alias:       []string{exitCmd},
			description: exitDesc,
		},
		executeCmd: {
			alias:       []string{executeCmd},
			description: executeDesc,
		},
		shellCmd: {
			alias:       []string{shellCmd},
			description: shellDesc,
		},
		lsCmd: {
			alias:       []string{lsCmd, "dir", "list"},
			description: lsDesc,
			cmdFunc:     ic.commandSftpList,
			isRemote:    true,
		},
		cdCmd: {
			alias:       []string{cdCmd, "chdir"},
			description: cdDesc,
			cmdFunc:     ic.commandSftpCd,
			isRemote:    true,
		},
		getCmd: {
			alias:       []string{getCmd, "download"},
			description: getDesc,
			usage:       getUsage,
			cmdFunc:     ic.commandSftpGet,
			isRemote:    true,
		},
		putCmd: {
			alias:       []string{putCmd, "upload"},
			description: putDesc,
			usage:       putUsage,
			cmdFunc:     ic.commandSftpPut,
			isRemote:    true,
		},
		mkdCmd: {
			alias:       []string{mkdCmd},
			description: mkdDesc,
			usage:       mkdUsage,
			cmdFunc:     ic.commandSftpMkdir,
			isRemote:    true,
		},
		rmCmd: {
			alias:       []string{rmCmd, "del", "delete"},
			description: rmDesc,
			usage:       rmUsage,
			cmdFunc:     ic.commandSftpRm,
			isRemote:    true,
		},
		statCmd: {
			alias:       []string{statCmd, "info"},
			description: statDesc,
			usage:       statUsage,
			cmdFunc:     ic.commandSftpStat,
			isRemote:    true,
		},
		mvCmd: {
			alias:       []string{mvCmd, "rename", "move"},
			description: mvDesc,
			usage:       mvUsage,
			cmdFunc:     ic.commandSftpMove,
			isRemote:    true,
		},
		pwdCmd: {
			alias:       []string{pwdCmd, "getwd"},
			description: pwdDesc,
			isRemote:    true,
		},
		// Local commands
		lPwdCmd: {
			alias:       []string{lPwdCmd, "lgetwd"},
			description: lPwdDesc,
			isRemote:    true,
		},
		lLsCmd: {
			alias:       []string{lLsCmd, "ldir", "llist"},
			description: lLsDesc,
			cmdFunc:     ic.commandSftpList,
			isRemote:    false,
		},
		lCdCmd: {
			alias:       []string{lCdCmd},
			description: lCdDesc,
			cmdFunc:     ic.commandSftpCd,
			isRemote:    false,
		},
		lMkdCmd: {
			alias:       []string{lMkdCmd},
			description: lMkdDesc,
			usage:       lMkdUsage,
			cmdFunc:     ic.commandSftpMkdir,
			isRemote:    false,
		},
	}

	if ic.cliSystem != "windows" {
		commands[chmodCmd] = sftpCommandStruck{
			alias:       []string{chmodCmd},
			description: chmodDesc,
			usage:       chmodUsage,
			cmdFunc:     ic.commandSftpChmod,
		}
	}

	return commands
}

func (ic *sftpConsole) printConsoleHelp() {
	tw := new(tabwriter.Writer)
	tw.Init(ic.console.Term, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommand\tDescription\t")
	_, _ = fmt.Fprintf(tw, "\n\t-------\t-----------\t\n")
	commands := ic.initSftpCommands()
	var cmdNames []string

	for k := range commands {
		cmdNames = append(cmdNames, k)
	}
	sort.Strings(cmdNames)

	for _, cmd := range cmdNames {
		aliases := strings.Join(commands[cmd].alias, ", ")
		_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", aliases, commands[cmd].description)
	}
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", "!command", "Execute \"command\" in local shell (non-interactive)")
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()

}
