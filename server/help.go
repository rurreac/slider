package server

import (
	"fmt"
	"golang.org/x/term"
	"sort"
	"text/tabwriter"
)

const serverHelp = `
Slider Server

  Creates a new Slider Server instance and waits for 
incoming Slider Client connections on the defined port.

  Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.

Usage: ./slider server [flags]

Flags:
`

// Console System Commands
const bgCmd = "bg"
const bgDesc = "Puts Console into background and returns to logging output"
const exitCmd = "exit"
const exitDesc = "Exits Console and terminates the Server"
const helpCmd = "help"
const helpDesc = "Shows this output"

// Console Execute Command
const executeCmd = "execute"
const executeDesc = "Runs a command remotely and returns the output"
const executeUsage = `

Usage: execute [flags] [command]

Flags:
`

// Console Sessions Command
const sessionsCmd = "sessions"
const sessionsDesc = "Interacts with Client Sessions"
const sessionsUsage = `

Usage: sessions [flags]

Flags:
`

// Console Socks Command
const socksCmd = "socks"
const socksDesc = "Runs / Stops a Socks server on the Client SSH Channel and a Listener to that channel on the Server"
const socksUsage = `

Usage: socks [flags]

Flags:
`

// Console Upload Command
const uploadCmd = "upload"
const uploadDesc = "Uploads file passed as an argument to Client"
const uploadUsage = `

Note that if no destination name is given, file will be uploaded with the same basename to the Client CWD.

Usage: upload [flags] [src] [dst]

Flags:
`

// Console Download Command
const downloadCmd = "download"
const downloadDesc = "Downloads file passed as an argument from Client"
const downloadUsage = `

* If no destination name is given, file will be downloaded with the same basename to the Server CWD.
* Downloading from a file list does not allow specifying destination.  

Usage: download [flags] [src] [dst]

Flags:
`

// Console Cert Command
const certsCmd = "certs"
const certsDesc = "Interacts with the Server Certificate Jar"
const certsUsage = `

Usage: certs [flags]

Flags:
`

type commandStruct struct {
	desc    string
	cmdFunc func(args ...string)
}

func (s *server) initCommands() map[string]commandStruct {
	var commands = map[string]commandStruct{
		bgCmd: {
			desc: bgDesc,
		},
		exitCmd: {
			desc: exitDesc,
		},
		helpCmd: {
			desc: helpDesc,
		},
		executeCmd: {
			desc:    executeDesc,
			cmdFunc: s.executeCommand,
		},
		sessionsCmd: {
			desc:    sessionsDesc,
			cmdFunc: s.sessionsCommand,
		},
		socksCmd: {
			desc:    socksDesc,
			cmdFunc: s.socksCommand,
		},
		uploadCmd: {
			desc:    uploadDesc,
			cmdFunc: s.uploadCommand,
		},
		downloadCmd: {
			desc:    downloadDesc,
			cmdFunc: s.downloadCommand,
		},
	}

	if s.authOn {
		commands[certsCmd] = commandStruct{
			desc:    certsDesc,
			cmdFunc: s.certsCommand,
		}
	}

	return commands
}

func (s *server) printConsoleHelp(console *term.Terminal) {
	tw := new(tabwriter.Writer)
	tw.Init(console, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommands\tDescription\t\n\n")
	commands := s.initCommands()
	var cmdNames []string

	for k, _ := range commands {
		cmdNames = append(cmdNames, k)
	}
	sort.Strings(cmdNames)

	for _, cmd := range cmdNames {
		_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", cmd, commands[cmd].desc)
	}
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
}
