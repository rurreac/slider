package server

import (
	"fmt"
	"golang.org/x/term"
	"text/tabwriter"
)

const serverHelpLong = `
Slider Server

  Creates a new Slider Server instance and waits for 
incoming Slider Client connections on the defined port.

  Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.

Usage: ./slider server [flags]

Flags:
`

func (s *server) printConsoleHelp(console *term.Terminal) {
	tw := new(tabwriter.Writer)
	tw.Init(console, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "\n\tCommands\tDescription\t\n\n")
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", bgCmd, bgShort)
	if s.authOn {
		_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", certsCmd, certsShort)
	}
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", downloadCmd, downloadShort)
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", executeCmd, executeShort)
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", exitCmd, exitShort)
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", helpCmd, helpShort)
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", sessionsCmd, sessionsShort)
	_, _ = fmt.Fprintf(tw, "\t%s\t%s\t\n", uploadCmd, uploadShort)
	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
}

// Console System Commands
const bgCmd = "bg"
const bgShort = "Puts Console into background and returns to logging output"
const exitCmd = "exit"
const exitShort = "Exits Console and terminates the Server"
const helpCmd = "help"
const helpShort = "Shows this output"

// Console Execute Command
const executeCmd = "execute"
const executeShort = "Runs a command remotely and returns the output"
const executeLong = `

Usage: execute [flags] [command]

Flags:
`

// Console Sessions Command
const sessionsCmd = "sessions"
const sessionsShort = "Interacts with Client Sessions"
const sessionsLong = `

Usage: sessions [flags]

Flags:
`

// Console Socks Command
const socksCmd = "socks"
const socksShort = "Runs / Stops a Socks server on the Client SSH Channel and a Listener to that channel on the Server"
const socksLong = `

Usage: socks [flags]

Flags:
`

// Console Upload Command
const uploadCmd = "upload"
const uploadShort = "Uploads file passed as an argument to Client"
const uploadLong = `

Note that if no destination name is given, file will be uploaded with the same basename to the Client CWD.

Usage: upload [flags] [src] [dst]

Flags:
`

// Console Download Command
const downloadCmd = "download"
const downloadShort = "Downloads file passed as an argument from Client"
const downloadLong = `

* If no destination name is given, file will be downloaded with the same basename to the Server CWD.
* Downloading from a file list does not allow specifying destination.  

Usage: download [flags] [src] [dst]

Flags:
`

// Console Cert Command
const certsCmd = "certs"
const certsShort = "Interacts with the Server Certificate Jar"
const certsLong = `

Usage: certs [flags]

Flags:
`
