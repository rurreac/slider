package server

import (
	"fmt"
	"sort"
	"text/tabwriter"
)

const (
	// Console CyanBold Commands
	bgCmd    = "bg"
	bgDesc   = "Puts Console into background and returns to logging output"
	exitCmd  = "exit"
	exitDesc = "Exits Console and terminates the Server"
	helpCmd  = "help"
	helpDesc = "Shows this output"

	// Console Execute Command
	executeCmd   = "execute"
	executeDesc  = "Runs a command remotely and returns the output"
	executeUsage = "Usage: execute [flags] [command]"

	// Console Sessions Command
	sessionsCmd   = "sessions"
	sessionsDesc  = "Interacts with Client Sessions"
	sessionsUsage = "When run without parameters, all available Sessions are listed." +
		"\n\n\rUsage: sessions [flags]"

	// Console Socks Command
	socksCmd   = "socks"
	socksDesc  = "Runs or Kills a Reverse Socks server"
	socksUsage = "Usage: socks [flags]"

	// Console SSH Command
	sshCmd   = "ssh"
	sshDesc  = "Opens an SSH session to a client"
	sshUsage = "Usage: ssh [flags]"

	// Console Shell Command
	shellCmd   = "shell"
	shellDesc  = "Binds to a client Shell"
	shellUsage = "Usage: shell [flags]"

	// Console Cert Command
	certsCmd   = "certs"
	certsDesc  = "Interacts with the Server Certificate Jar"
	certsUsage = "When run without parameters, all available Slider key pairs are listed." +
		"\n\n\rUsage: certs [flags]"

	// Console Client Connect Command
	connectCmd   = "connect"
	connectDesc  = "Receives the address of a Client to connect to"
	connectUsage = "Usage: connect [flags] <[client_address]:port>"

	// Console Port Forwarding Command
	portFwdCmd   = "portfwd"
	portFwdDesc  = "Creates a port forwarding tunnel to a client"
	portFwdUsage = "Usage: portfwd [flags] <[addressA]:portA:[addressB]:portB>"
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
		portFwdCmd: {
			desc:    portFwdDesc,
			cmdFunc: s.portFwdCommand,
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
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", "!command", "Execute \"command\" in local shell (non-interactive)")
	_, _ = fmt.Fprintln(tw)
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
}
