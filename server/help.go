package server

import (
	"fmt"
	"sort"
	"text/tabwriter"
)

const (
	serverHelp = `
Slider Server

  Creates a new Slider Server instance and waits for 
incoming Slider Client connections on the defined port.

  Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.

Usage: <slider_server> [flags]

Flags:`

	// Console System Commands
	bgCmd    = "bg"
	bgDesc   = "Puts Console into background and returns to logging output"
	exitCmd  = "exit"
	exitDesc = "Exits Console and terminates the Server"
	helpCmd  = "help"
	helpDesc = "Shows this output"

	// Console Execute Command
	executeCmd   = "execute"
	executeDesc  = "Runs a command remotely and returns the output"
	executeUsage = `

Usage: execute [flags] [command]

Flags:
`

	// Console Sessions Command
	sessionsCmd   = "sessions"
	sessionsDesc  = "Interacts with Client Sessions"
	sessionsUsage = `

When run without parameters, all available Sessions will be listed.

Usage: sessions [flags]

Flags:
`

	// Console Socks Command
	socksCmd   = "socks"
	socksDesc  = "Runs or Kills a Reverse Socks server"
	socksUsage = `

Usage: socks [flags]

Flags:
`

	// Console SSH Command
	sshCmd   = "ssh"
	sshDesc  = "Opens an SSH session to a client"
	sshUsage = `

Usage: ssh [flags]

Flags:
`

	// Console Shell Command
	shellCmd   = "shell"
	shellDesc  = "Binds to a client Shell"
	shellUsage = `

Usage: shell [flags]

Flags:
`

	// Console Upload Command
	uploadCmd   = "upload"
	uploadDesc  = "Uploads file passed as an argument to Client"
	uploadUsage = `

Note that if no destination name is given, file will be uploaded with the same basename to the Client CWD.
Use -sftp flag for more reliable transfer of large files with progress reporting.

Usage: upload [flags] [src] [dst]

Flags:
`

	// Console Download Command
	downloadCmd   = "download"
	downloadDesc  = "Downloads file passed as an argument from Client"
	downloadUsage = `

* If no destination name is given, file will be downloaded with the same basename to the Server CWD.
* Downloading from a file list does not allow specifying destination.
* Use -sftp flag for more reliable transfer of large files with progress reporting.

Usage: download [flags] [src] [dst]

Flags:
`

	// Console Cert Command
	certsCmd   = "certs"
	certsDesc  = "Interacts with the Server Certificate Jar"
	certsUsage = `

When run without parameters, all available KeyPairs in the Certificate Jar will be listed.

Usage: certs [flags]

Flags:
`

	// Console Client Connect Command
	connectCmd   = "connect"
	connectDesc  = "Receives the address of a Client to connect to"
	connectUsage = `

Connects to a Client configured as Listener and creates a new Session

Usage: connect [flags] <[client_address]:port>

Flags:
`
)

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
		sshCmd: {
			desc:    sshDesc,
			cmdFunc: s.sshCommand,
		},
		connectCmd: {
			desc:    connectDesc,
			cmdFunc: s.connectCommand,
		},
		shellCmd: {
			desc:    shellDesc,
			cmdFunc: s.shellCommand,
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

func (s *server) printConsoleHelp() {
	tw := new(tabwriter.Writer)
	tw.Init(s.console.Term, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommand\tDescription\t")
	_, _ = fmt.Fprintf(tw, "\n\t-------\t-----------\t\n")
	commands := s.initCommands()
	var cmdNames []string

	for k := range commands {
		cmdNames = append(cmdNames, k)
	}
	sort.Strings(cmdNames)

	for _, cmd := range cmdNames {
		_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", cmd, commands[cmd].desc)
	}
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
}
