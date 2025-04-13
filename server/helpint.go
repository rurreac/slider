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
	lsDesc = "List directory contents"
	// Get directory
	pwdCmd  = "pwd"
	pwdDesc = "Show current remote directory"
	// Change dir
	cdCmd  = "cd"
	cdDesc = "Change directory"
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
	mkdDesc  = "Create directory"
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
)

type sftpCommandStruck struct {
	cmd         string
	alias       []string
	cmdFunc     func(request *intCommandRequest)
	description string
	usage       string
}

func (ic *intConsole) initInteractCommands() map[string]sftpCommandStruck {
	var commands = map[string]sftpCommandStruck{
		lsCmd: {
			cmd:         lsCmd,
			alias:       []string{lsCmd, "dir", "list"},
			description: lsDesc,
			cmdFunc:     ic.commandIntList,
		},
		cdCmd: {
			cmd:         cdCmd,
			alias:       []string{cdCmd, "chdir"},
			description: cdDesc,
			cmdFunc:     ic.commandIntCd,
		},
		getCmd: {
			alias:       []string{getCmd, "download"},
			description: getDesc,
			usage:       getUsage,
			cmdFunc:     ic.commandIntGet,
		},
		putCmd: {
			alias:       []string{putCmd, "upload"},
			description: putDesc,
			usage:       putUsage,
			cmdFunc:     ic.commandIntPut,
		},
		mkdCmd: {
			alias:       []string{mkdCmd},
			description: mkdDesc,
			usage:       mkdUsage,
			cmdFunc:     ic.commandIntMkdir,
		},
		rmCmd: {
			alias:       []string{rmCmd, "del", "delete"},
			description: rmDesc,
			usage:       rmUsage,
			cmdFunc:     ic.commandIntRm,
		},
		statCmd: {
			alias:       []string{statCmd, "info"},
			description: statDesc,
			usage:       statUsage,
			cmdFunc:     ic.commandIntStat,
		},
		mvCmd: {
			alias:       []string{mvCmd, "rename", "move"},
			description: mvDesc,
			usage:       mvUsage,
			cmdFunc:     ic.commandIntMove,
		},
		pwdCmd: {
			alias:       []string{pwdCmd, "getwd"},
			description: pwdDesc,
		},
		// Common commands
		shellCmd: {
			alias:       []string{shellCmd},
			description: shellDesc,
		},
		helpCmd: {
			alias:       []string{helpCmd},
			description: helpDesc,
		},
		exitCmd: {
			alias:       []string{exitCmd},
			description: exitDesc,
		},
	}

	if ic.cliSystem != "windows" {
		commands[chmodCmd] = sftpCommandStruck{
			alias:       []string{chmodCmd},
			description: chmodDesc,
			usage:       chmodUsage,
			cmdFunc:     ic.commandIntChmod,
		}
	}

	return commands
}

func (ic *intConsole) printInteractiveConsoleHelp() {
	tw := new(tabwriter.Writer)
	tw.Init(ic.console.Term, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommand\tDescription\t")
	_, _ = fmt.Fprintf(tw, "\n\t-------\t-----------\t\n")
	commands := ic.initInteractCommands()
	var cmdNames []string

	for k := range commands {
		cmdNames = append(cmdNames, k)
	}
	sort.Strings(cmdNames)

	for _, cmd := range cmdNames {
		aliases := strings.Trim(strings.Replace(fmt.Sprint(commands[cmd].alias), " ", ", ", -1), "[]")
		_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", aliases, commands[cmd].description)
	}
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()

}
