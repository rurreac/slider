package server

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/sio"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/term"
)

type Console struct {
	Term      *term.Terminal
	InitState *term.State
	Output    *log.Logger
}

func (s *server) NewConsole() string {
	var out string

	// Set Console Colors
	setConsoleColors()

	// Get available Commands
	commands := s.initCommands()

	// Initialize Term
	s.console.InitState, _ = term.MakeRaw(int(os.Stdin.Fd()))
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), s.console.InitState)
	}()

	screen := struct {
		io.Reader
		io.Writer
	}{os.Stdin, os.Stdout}

	// Set Console
	s.console.Term = term.NewTerminal(screen, "")

	// List of the Ordered the commands for autocompletion
	var cmdList []string
	for k := range commands {
		cmdList = append(cmdList, k)
	}
	slices.Sort(cmdList)

	// Simple autocompletion
	s.console.Term.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		// If TAB key is pressed and text was written
		if key == 9 && len(line) > 0 {
			newLine, newPos := s.autocompleteCommand(line, cmdList)
			return newLine, newPos, true
		}
		return line, pos, false
	}

	s.console.Output = log.New(s.console.Term, "", 0)

	// Set Console
	if width, height, tErr := term.GetSize(int(os.Stdin.Fd())); tErr == nil {
		// Disregard the error if fails setting Console size
		_ = s.console.Term.SetSize(width, height)
	}
	s.console.PrintlnWarn(
		"\r\nPress CTRL^C again or Type \"bg\" to background the console," +
			"\r\nType \"exit\" to terminate the server.\r\n",
	)

	s.console.Term.SetPrompt(getPrompt())

	for consoleInput := true; consoleInput; {
		var fCmd string
		input, err := s.console.Term.ReadLine()
		if err != nil {
			if err != io.EOF {
				s.console.Printf("\rFailed to read input: %s\r\n", err)
				break
			}
			// From 'term' documentation, CTRL^C as well as CTR^D return:
			// line, error = "", io.EOF
			// We will background gracefully when this happens
			s.console.PrintlnWarn("\r\nLogging...\r\n")
			return "bg"
		}
		args := make([]string, 0)
		args = append(args, strings.Fields(input)...)

		if len(args) > 0 {
			fCmd = args[0]
		}

		switch fCmd {
		case exitCmd, bgCmd:
			consoleInput = false
			out = fCmd
		case helpCmd:
			s.printConsoleHelp()
		case "":
			continue
		default:
			currentPrompt := getPrompt()
			if k, ok := commands[fCmd]; ok {
				k.cmdFunc(args[1:]...)
			} else {
				s.notConsoleCommand(args)
			}
			s.console.Term.SetPrompt(currentPrompt)
		}
	}

	return out
}

func (s *server) autocompleteCommand(input string, cmdList []string) (string, int) {
	var cmd string
	var substring string
	var count int

	for _, c := range cmdList {
		if strings.HasPrefix(c, input) {
			cmd = c
			substring = strings.SplitAfter(c, input)[0]
			count++
		} else if count == 1 {
			return cmd, len(cmd)
		}
	}

	if count == 1 {
		return cmd, len(cmd)
	}

	if count == 0 {
		substring = input
	}

	return substring, len(substring)
}

func (s *server) notConsoleCommand(fCmd []string) {
	s.console.PrintWarnSelect("Console does not recognize Command: ", fCmd...)

	// If a Shell was not set just return
	if s.serverInterpreter.Shell == "" {
		return
	}

	// Else, we'll try to execute the command locally
	s.console.PrintlnWarn("Will run an OS command locally instead...")
	fCmd = append(s.serverInterpreter.CmdArgs, strings.Join(fCmd, " "))

	cmd := exec.Command(s.serverInterpreter.Shell, fCmd...) //nolint:gosec
	cmd.Stdout = s.console.Term
	cmd.Stderr = s.console.Term
	if err := cmd.Run(); err != nil {
		s.console.PrintlnErrorStep("%v", err)
	}
	s.console.Println("")

}

func (s *server) executeCommand(args ...string) {
	executeFlags := flag.NewFlagSet(executeCmd, flag.ContinueOnError)
	executeFlags.SetOutput(s.console.Term)
	eSession := executeFlags.Int("s", 0, "Runs given command on a Session ID")
	eAll := executeFlags.Bool("a", false, "Runs given command on every Session")
	executeFlags.Usage = func() {
		s.console.PrintCommandUsage(executeFlags, executeDesc+executeUsage)
	}

	if pErr := executeFlags.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 || (*eAll && *eSession > 0) || (!*eAll && *eSession == 0) {
		executeFlags.Usage()
		return
	}

	var sessions []*Session
	if *eSession > 0 {
		session, sessErr := s.getSession(*eSession)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *eSession)
			return
		}
		sessions = []*Session{session}
	}

	if *eAll {
		for _, session := range s.sessionTrack.Sessions {
			sessions = append(sessions, session)
		}
	}

	for _, session := range sessions {
		if *eAll {
			s.console.PrintWarnSelect(
				"Executing Command on ",
				fmt.Sprintf("SessionID %d", session.sessionID),
			)
		}
		if _, _, err := session.sendRequest(
			"session-exec",
			true,
			[]byte(strings.Join(executeFlags.Args(), " ")),
		); err != nil {
			s.console.PrintlnErrorStep("%v", err)
			continue
		}

		cmdOut, sErr := session.sessionExecute()
		if sErr != nil {
			s.console.PrintlnErrorStep("%v", sErr)
			continue
		}
		s.console.Printf("%s", cmdOut)
	}
}

func (s *server) sessionsCommand(args ...string) {
	var list bool
	sessionsFlags := flag.NewFlagSet(sessionsCmd, flag.ContinueOnError)
	sessionsFlags.SetOutput(s.console.Term)

	sInteract := sessionsFlags.Int("i", 0, "Starts Interactive Shell on a Session ID")
	sDisconnect := sessionsFlags.Int("d", 0, "Disconnect Session ID")
	sKill := sessionsFlags.Int("k", 0, "Kills Session ID")
	sessionsFlags.Usage = func() {
		s.console.PrintCommandUsage(sessionsFlags, sessionsDesc+sessionsUsage)
	}

	if pErr := sessionsFlags.Parse(args); pErr != nil {
		return
	}

	if len(args) == 0 {
		list = true
	}

	if !list && ((*sInteract > 0 && *sKill > 0 && *sDisconnect > 0) || (*sInteract == 0 && *sKill == 0 && *sDisconnect == 0)) {
		s.console.Printf("Flags '-i', '-d' and '-k' are mutually exclusive, nor can have 0 value.")
		return
	}

	if sessionsFlags.NArg() > 0 {
		s.console.Printf("Unexpected arguments: %s", sessionsFlags.Args())
		sessionsFlags.Usage()
		return
	}

	var err error

	if list {
		if len(s.sessionTrack.Sessions) > 0 {
			var keys []int
			for i := range s.sessionTrack.Sessions {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			tw := new(tabwriter.Writer)
			tw.Init(s.console.Term, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintf(tw, "\n\tID\tSystem\tUser\tHost\tIO\tConnection\tSocks\tFingerprint\t\n")

			for _, i := range keys {
				session := s.sessionTrack.Sessions[int64(i)]
				socksPort := fmt.Sprintf("%d", session.SocksInstance.Port)
				if socksPort == "0" {
					socksPort = "--"
				}

				if session.ClientInterpreter != nil {
					fingerprint := session.fingerprint
					if fingerprint == "" {
						fingerprint = "--"
					}
					var inOut = "<-"
					if session.isListener {
						inOut = "->"
					}
					_, _ = fmt.Fprintf(tw, "\t%d\t%s/%s\t%s\t%s\t%s\t%s\t%s\t%s\t\n",
						session.sessionID,
						session.ClientInterpreter.Arch,
						session.ClientInterpreter.System,
						session.ClientInterpreter.User,
						session.ClientInterpreter.Hostname,
						inOut,
						session.wsConn.RemoteAddr().String(),
						socksPort,
						fingerprint,
					)

				}
			}
			_, _ = fmt.Fprintln(tw)
			_ = tw.Flush()
		}
		s.console.Printf("Active sessions: %d\n", s.sessionTrack.SessionActive)
		return
	}

	if *sInteract > 0 {
		session, sessErr := s.getSession(*sInteract)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sInteract)
			return
		}
		if _, _, err = session.sendRequest(
			"session-shell",
			true,
			nil,
		); err != nil {
			s.console.Printf("%s", err)
			return
		}
		session.sessionInteractive(s.console.InitState, s.serverInterpreter.WinChangeCall)
		return
	}

	if *sDisconnect > 0 {
		session, sessErr := s.getSession(*sDisconnect)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sDisconnect)
			return
		}
		if cErr := session.wsConn.Close(); cErr != nil {
			s.console.PrintlnErrorStep("Failed to close connection to Session ID %d", session.sessionID)
			return
		}
		s.console.PrintlnOkStep("Closed connection to Session ID %d", session.sessionID)
		return
	}

	if *sKill > 0 {
		session, sessErr := s.getSession(*sKill)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *sKill)
			return
		}
		if _, _, err = session.sendRequest(
			"shutdown",
			true,
			nil,
		); err != nil {
			s.console.PrintlnErrorStep("Client did not answer properly to the request: %s", err)
			return
		}
		s.console.PrintlnOkStep("SessionID %d terminated gracefully", *sKill)

		return
	}
}

func (s *server) socksCommand(args ...string) {
	socksFlags := flag.NewFlagSet(socksCmd, flag.ContinueOnError)
	socksFlags.SetOutput(s.console.Term)
	sSession := socksFlags.Int("s", 0, "Runs a Socks5 server over an SSH Channel on a Session ID")
	sPort := socksFlags.Int("p", 0, "Uses this port number as local Listener, otherwise randomly selected")
	sKill := socksFlags.Int("k", 0, "Kills Socks5 Listener and Server on a Session ID")
	socksFlags.Usage = func() {
		s.console.PrintCommandUsage(socksFlags, socksDesc+socksUsage)
	}

	if pErr := socksFlags.Parse(args); pErr != nil {
		return
	}

	var session *Session
	var sessErr error
	if (*sSession == 0 && *sKill == 0) || (*sSession > 0 && *sKill > 0) {
		socksFlags.Usage()
		return
	} else {
		sessionID := *sSession + *sKill
		session, sessErr = s.getSession(sessionID)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", sessionID)
			return
		}
	}

	if *sKill > 0 {
		if session.SocksInstance.IsEnabled() {
			if err := session.SocksInstance.Stop(); err != nil {
				s.console.PrintlnErrorStep("%v", err)
				return
			}
			s.console.PrintlnOkStep("Socks Endpoint gracefully stopped")
			return
		}
		s.console.PrintlnDebugStep("No Socks Server found running on Session ID %d", *sKill)
		return
	}

	if *sSession > 0 {
		if session.SocksInstance.IsEnabled() {
			s.console.PrintlnErrorStep("Socks Endpoint is already running on Port: %d", session.SocksInstance.Port)
			return
		}
		s.console.PrintlnDebugStep("Enabling Socks5 Endpoint in the background")

		go session.socksEnable(*sPort)

		// Give some time to check
		socksTicker := time.NewTicker(250 * time.Millisecond)
		timeout := time.Now().Add(conf.Timeout)
		for range socksTicker.C {
			if time.Now().Before(timeout) {
				port, _ := session.SocksInstance.GetEndpointPort()
				if port == 0 {
					continue
				}
				s.console.PrintlnOkStep("Socks Endpoint running on Port: %d", port)
				return
			}
			s.console.PrintlnErrorStep("Socks Endpoint doesn't appear to be running")
			return
		}
	}

	socksFlags.Usage()
}

func (s *server) uploadCommand(args ...string) {
	uploadFlags := flag.NewFlagSet(uploadCmd, flag.ContinueOnError)
	uploadFlags.SetOutput(s.console.Term)
	uSession := uploadFlags.Int("s", 0, "Uploads file to selected Session ID")
	uSFTP := uploadFlags.Bool("sftp", false, "Use SFTP protocol for file transfer (more reliable for large files)")
	uploadFlags.Usage = func() {
		s.console.PrintCommandUsage(uploadFlags, uploadDesc+uploadUsage)
	}

	if pErr := uploadFlags.Parse(args); pErr != nil {
		return
	}

	if len(uploadFlags.Args()) > 2 || len(uploadFlags.Args()) < 1 {
		uploadFlags.Usage()
		return
	}

	if *uSession > 0 {
		session, sessErr := s.getSession(*uSession)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *uSession)
			return
		}

		src := uploadFlags.Args()[0]
		dst := filepath.Base(src)
		if len(uploadFlags.Args()) == 2 {
			dst = uploadFlags.Args()[1]
		}

		// Check if file exists
		fileInfo, err := os.Stat(src)
		if err != nil {
			s.console.PrintlnErrorStep("Failed to access source file: %v", err)
			return
		}

		if fileInfo.IsDir() {
			s.console.PrintlnErrorStep("Directory upload is not supported, please specify a file")
			return
		}

		fileSize := fileInfo.Size()

		// Use SFTP for file transfer if requested
		if *uSFTP {
			s.console.PrintlnDebugStep("Using SFTP protocol for file upload")
			s.console.PrintlnDebugStep("Uploading %s to %s (%.2f KB)", src, dst, float64(fileSize)/1024.0)

			// Open SFTP client
			sftpClient, err := session.openSFTPClient()
			if err != nil {
				s.console.PrintlnErrorStep("Failed to establish SFTP connection: %v", err)
				return
			}
			defer sftpClient.Close()

			// Open local file
			lFile, err := os.Open(src)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to open local file: %v", err)
				return
			}
			defer lFile.Close()

			// Create remote file
			rFile, err := sftpClient.Create(dst)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to create remote file: %v", err)
				return
			}
			defer rFile.Close()

			// Copy with progress reporting
			_, err = CopyWithProgress(rFile, lFile, s.console, src, dst, fileSize, "Upload")
			if err != nil {
				s.console.PrintlnErrorStep("Failed to upload file: %v", err)
				return
			}
		} else {
			// Use the traditional method
			for statusChan := range session.uploadFile(src, dst) {
				if statusChan.Success {
					s.console.PrintlnOkStep("Uploaded \"%s\" -> \"%s\"",
						src,
						statusChan.FileName,
					)
				} else {
					s.console.PrintlnErrorStep("Failed to Upload \"%s\": %v", src, statusChan.Err)
				}
			}
		}
	} else {
		uploadFlags.Usage()
	}
}

func (s *server) downloadCommand(args ...string) {
	downloadFlags := flag.NewFlagSet(downloadCmd, flag.ContinueOnError)
	downloadFlags.SetOutput(s.console.Term)
	dSession := downloadFlags.Int("s", 0, "Downloads file from a given a Session ID")
	dFile := downloadFlags.String("f", "", "Receives a file list with items to download")
	dSFTP := downloadFlags.Bool("sftp", false, "Use SFTP protocol for file transfer (more reliable for large files)")
	downloadFlags.Usage = func() {
		s.console.PrintCommandUsage(downloadFlags, downloadDesc+downloadUsage)
	}

	if pErr := downloadFlags.Parse(args); pErr != nil {
		return
	}

	if *dSession == 0 {
		downloadFlags.Usage()
		return
	}

	if *dSession > 0 {
		session, sessErr := s.getSession(*dSession)
		if sessErr != nil {
			s.console.PrintlnDebugStep("Unknown Session ID %d", *dSession)
			return
		}

		if *dFile == "" && downloadFlags.NFlag() >= 2 && !*dSFTP {
			s.console.PrintlnDebugStep("Need to provide a file list")
			return
		} else if *dFile != "" {
			// Batch download mode - SFTP not supported for batch downloads
			if *dSFTP {
				s.console.PrintlnDebugStep("SFTP mode is not supported for batch downloads, using standard method")
			}

			s.console.PrintlnDebugStep("Output Dir: \"%s\"", sio.GetSliderHome())

			for statusChan := range session.downloadFileBatch(*dFile) {
				if statusChan.Success {
					s.console.PrintlnOkStep("Downloaded \"%s\"",
						statusChan.FileName,
					)
				} else {
					s.console.PrintlnErrorStep("Failed to Download \"%v\"", statusChan.Err)
				}
			}
			return
		}

		if len(downloadFlags.Args()) > 2 || len(downloadFlags.Args()) < 1 {
			s.console.PrintlnDebugStep("Incorrect number of arguments")
			return
		}

		src := downloadFlags.Args()[0]
		dst := filepath.Base(src)
		if len(downloadFlags.Args()) == 2 {
			dst = downloadFlags.Args()[1]
		}

		// Use SFTP for file transfer if requested
		if *dSFTP {
			s.console.PrintlnDebugStep("Using SFTP protocol for file download")

			// Open SFTP client
			sftpClient, err := session.openSFTPClient()
			if err != nil {
				s.console.PrintlnErrorStep("Failed to establish SFTP connection: %v", err)
				return
			}
			defer sftpClient.Close()

			// Get file info
			fileInfo, err := sftpClient.Stat(src)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to access remote file: %v", err)
				return
			}

			if fileInfo.IsDir() {
				s.console.PrintlnErrorStep("Directory download is not supported, please specify a file")
				return
			}

			fileSize := fileInfo.Size()
			s.console.PrintlnDebugStep("Downloading %s to %s (%.2f KB)", src, dst, float64(fileSize)/1024.0)

			// Open remote file
			rFile, err := sftpClient.Open(src)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to open remote file: %v", err)
				return
			}
			defer rFile.Close()

			// Create local file
			lFile, err := os.Create(dst)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to create local file: %v", err)
				return
			}
			defer lFile.Close()

			// Copy with progress reporting
			_, err = CopyWithProgress(lFile, rFile, s.console, src, dst, fileSize, "Download")
			if err != nil {
				s.console.PrintlnErrorStep("Failed to download file: %v", err)
				return
			}
		} else {
			// Use the traditional method
			for statusChan := range session.downloadFile(src, dst) {
				if statusChan.Success {
					s.console.PrintlnOkStep("Downloaded \"%s\" -> \"%s\"",
						src,
						statusChan.FileName,
					)
				} else {
					s.console.PrintlnErrorStep("Failed to Download \"%s\": %v", src, statusChan.Err)
				}
			}
		}
	}
}

func (s *server) certsCommand(args ...string) {
	var list bool
	certsFlags := flag.NewFlagSet(certsCmd, flag.ContinueOnError)
	certsFlags.SetOutput(s.console.Term)
	cNew := certsFlags.Bool("n", false, "Generate a new Key Pair")
	cRemove := certsFlags.Int("r", 0, "Remove matching index from the Certificate Jar")
	certsFlags.Usage = func() {
		s.console.PrintCommandUsage(certsFlags, certsDesc+certsUsage)
	}
	if err := certsFlags.Parse(args); err != nil {
		return
	}

	if *cNew && *cRemove > 0 {
		s.console.Printf("Flags '-n' and '-k' are mutually exclusive.")
		return
	}

	if !*cNew && *cRemove == 0 || len(args) == 0 {
		list = true
	}

	if *cRemove > 0 {
		if err := s.dropCertItem(int64(*cRemove)); err != nil {
			s.console.PrintlnErrorStep("%s", err)
			return
		}
		s.console.PrintlnOkStep("Certificate successfully removed")
		return
	}

	if list {
		if len(s.certTrack.Certs) > 0 {
			var keys []int
			for i := range s.certTrack.Certs {
				keys = append(keys, int(i))
			}
			sort.Ints(keys)

			twl := new(tabwriter.Writer)
			twl.Init(s.console.Term, 0, 4, 2, ' ', 0)

			for _, k := range keys {
				_, _ = fmt.Fprintln(twl)
				_, _ = fmt.Fprintf(twl, "\tCertID %d\n\t%s\n",
					k,
					strings.Repeat("-", 11),
				)
				_, _ = fmt.Fprintf(twl, "\tPrivate Key:\t%s\t\n", s.certTrack.Certs[int64(k)].PrivateKey)
				_, _ = fmt.Fprintf(twl, "\tFingerprint:\t%s\t\n", s.certTrack.Certs[int64(k)].FingerPrint)
				_, _ = fmt.Fprintf(twl, "\tUsed by Session:\t%d\t\n", s.getSessionByCert(s.certTrack.Certs[int64(k)].FingerPrint))
			}
			_, _ = fmt.Fprintln(twl)
			_ = twl.Flush()
		}
		s.console.Printf("Certificates in Jar: %d\n", s.certTrack.CertActive)
		return
	}

	if *cNew {
		keypair, err := s.newCertItem()
		if err != nil {
			s.console.PrintlnErrorStep("Failed to generate certificate - %s", err)
		}
		twn := new(tabwriter.Writer)
		twn.Init(s.console.Term, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(twn)
		_, _ = fmt.Fprintf(twn, "\tPrivate Key:\t%s\t\n", keypair.PrivateKey)
		_, _ = fmt.Fprintf(twn, "\tFingerprint:\t%s\t\n", keypair.FingerPrint)
		_, _ = fmt.Fprintln(twn)
		_ = twn.Flush()

		return
	}
}

func (s *server) connectCommand(args ...string) {
	connectFlags := flag.NewFlagSet(connectCmd, flag.ContinueOnError)
	connectFlags.SetOutput(s.console.Term)
	connectFlags.Usage = func() {
		s.console.PrintCommandUsage(connectFlags, connectDesc+connectUsage)
	}
	if err := connectFlags.Parse(args); err != nil {
		return
	}
	if len(connectFlags.Args()) == 0 || len(connectFlags.Args()) > 1 {
		connectFlags.Usage()
		return
	}
	clientAddr, rErr := net.ResolveTCPAddr("tcp", connectFlags.Args()[0])
	if rErr != nil {
		s.console.PrintlnErrorStep("Argument \"%s\" is not a valid address", connectFlags.Args()[0])
		return
	}
	var ip = clientAddr.IP.String()
	if clientAddr.IP == nil {
		ip = "127.0.0.1"
	}
	s.console.PrintlnDebugStep("Establishing Connection to %s:%d (Timeout: %s)", ip, clientAddr.Port, conf.Timeout)

	notifier := make(chan bool, 1)
	timeout := time.Now().Add(conf.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)

	go s.newClientConnector(clientAddr, notifier)

	for {
		select {
		case connected := <-notifier:
			if connected {
				s.console.PrintlnOkStep("Successfully connected to Client %s:%d", ip, clientAddr.Port)
				close(notifier)
				return
			} else {
				s.console.PrintlnErrorStep("Failed to connect to Client %s:%d", ip, clientAddr.Port)
				close(notifier)
				return
			}
		case t := <-ticker.C:
			if t.After(timeout) {
				s.console.PrintlnErrorStep("Timed out connecting to Client %s:%d", ip, clientAddr.Port)
				close(notifier)
				return
			}
		}
	}
}

func (s *server) sftpCommand(args ...string) {
	// Set up command flags
	sftpFlags := flag.NewFlagSet(sftpCmd, flag.ContinueOnError)
	sftpFlags.SetOutput(s.console.Term)
	sSession := sftpFlags.Int("s", 0, "Session ID to establish SFTP connection with")
	sftpFlags.Usage = func() {
		s.console.PrintCommandUsage(sftpFlags, sftpDesc+sftpUsage)
	}

	// Parse flags
	if pErr := sftpFlags.Parse(args); pErr != nil {
		return
	}

	// Validate session ID
	if *sSession == 0 {
		s.console.PrintlnDebugStep("Session ID is required")
		sftpFlags.Usage()
		return
	}

	// Get session
	session, sessErr := s.getSession(*sSession)
	if sessErr != nil {
		s.console.PrintlnDebugStep("Unknown Session ID %d", *sSession)
		return
	}

	// Open SFTP client
	s.console.PrintlnDebugStep("Establishing SFTP connection to session %d...", *sSession)
	sftpClient, err := session.openSFTPClient()
	if err != nil {
		s.console.PrintlnErrorStep("Failed to establish SFTP connection: %v", err)
		return
	}
	defer sftpClient.Close()

	s.console.PrintlnOkStep("SFTP connection established successfully")

	// Start interactive SFTP session
	s.startInteractiveSFTPSession(session, sftpClient)
}

// startInteractiveSFTPSession provides an interactive SFTP session
func (s *server) startInteractiveSFTPSession(session *Session, sftpClient *sftp.Client) {
	// Get current remote directory for prompt
	remoteCwd, err := sftpClient.Getwd()
	if err != nil {
		remoteCwd = "/"
		s.console.PrintlnErrorStep("Unable to determine remote directory: %v", err)
	}

	// Define SFTP prompt
	sftpPrompt := func() string {
		return fmt.Sprintf("[SFTP][%s]> ", remoteCwd)
	}

	// Print welcome message and help info
	s.console.PrintlnDebugStep("Starting interactive SFTP session")
	s.console.PrintlnDebugStep("Type 'help' for available commands, 'exit' to quit")

	// Set the terminal prompt
	s.console.Term.SetPrompt(sftpPrompt())

	// Command loop
	for {
		// Display prompt and get command
		cmd, err := s.console.Term.ReadLine()
		if err != nil {
			s.console.PrintlnErrorStep("Error reading command: %v", err)
			break
		}

		// Trim the command
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}

		// Split the command into parts
		cmdParts := strings.Fields(cmd)
		command := strings.ToLower(cmdParts[0])
		args := cmdParts[1:]

		// Process commands
		switch command {
		case "help":
			s.printSFTPHelp()

		case "pwd", "getwd":
			// Print working directory
			s.console.PrintlnDebugStep("Current remote directory: %s", remoteCwd)

		case "ls", "dir", "list":
			// List directory contents
			path := remoteCwd
			if len(args) > 0 {
				path = args[0]
			}

			// If path is relative, join with current directory
			if !filepath.IsAbs(path) && path != "." {
				path = filepath.Join(remoteCwd, path)
			}

			s.console.PrintlnDebugStep("Listing directory: %s", path)
			entries, err := sftpClient.ReadDir(path)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to list directory: %v", err)
				continue
			}

			if len(entries) == 0 {
				s.console.PrintlnDebugStep("Directory is empty")
				continue
			}

			// Display entries in columns
			tw := new(tabwriter.Writer)
			tw.Init(s.console.Term, 0, 4, 2, ' ', 0)

			// Print header
			_, _ = fmt.Fprintf(tw, "Type\tPermissions\tSize\tModified\tName\t\n")
			_, _ = fmt.Fprintf(tw, "----\t-----------\t----\t--------\t----\t\n")

			for _, entry := range entries {
				entryType := "-"
				if entry.IsDir() {
					entryType = "d"
				} else if entry.Mode()&os.ModeSymlink != 0 {
					entryType = "l"
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

				// Format: type permissions size modified name
				_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t\n",
					entryType,
					entry.Mode().String(),
					size,
					entry.ModTime().Format("Jan 02 15:04"),
					entry.Name())
			}
			_ = tw.Flush()

		case "cd", "chdir":
			// Change directory
			if len(args) < 1 {
				// When called without arguments, go to home directory
				// For simplicity, we'll use "/" as the home directory
				remoteCwd = "/"
				s.console.PrintlnOkStep("Changed directory to: %s", remoteCwd)
				s.console.Term.SetPrompt(sftpPrompt())
				continue
			}

			// Handle special paths
			newPath := args[0]

			// Handle "." (current directory) - no change needed
			if newPath == "." {
				s.console.PrintlnDebugStep("Staying in current directory: %s", remoteCwd)
				continue
			}

			// Handle ".." (parent directory)
			if newPath == ".." {
				// Get parent directory
				parentPath := filepath.Dir(remoteCwd)
				if parentPath == remoteCwd {
					// Already at root
					s.console.PrintlnDebugStep("Already at root directory")
					continue
				}
				newPath = parentPath
			} else if !filepath.IsAbs(newPath) {
				// Relative path, join with current directory
				newPath = filepath.Join(remoteCwd, newPath)
			}

			// Check if directory exists and is accessible
			fi, err := sftpClient.Stat(newPath)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to access directory: %v", err)
				continue
			}

			if !fi.IsDir() {
				s.console.PrintlnErrorStep("Not a directory: %s", newPath)
				continue
			}

			// Update the current directory
			remoteCwd = newPath
			s.console.PrintlnOkStep("Changed directory to: %s", remoteCwd)

			// Update the prompt
			s.console.Term.SetPrompt(sftpPrompt())

		case "get", "download":
			// Download a file from client to server
			recursive := false
			args = s.parseRecursiveFlag(args, &recursive)

			if len(args) < 1 {
				s.console.PrintlnErrorStep("Usage: get [-r] <remote_path> [local_path]")
				s.console.PrintlnDebugStep("  -r: Download directories recursively")
				continue
			}

			// Process remote file path
			remotePath := args[0]
			if !filepath.IsAbs(remotePath) {
				remotePath = filepath.Join(remoteCwd, remotePath)
			}

			// Get file info to check if it exists
			fi, err := sftpClient.Stat(remotePath)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to access remote path: %v", err)
				continue
			}

			// Determine local path
			localPath := filepath.Base(remotePath)
			if len(args) > 1 {
				localPath = args[1]
			}

			// Handle differently based on whether it's a directory or file
			if fi.IsDir() {
				if !recursive {
					s.console.PrintlnErrorStep("Cannot download a directory without -r flag")
					continue
				}

				// Recursive directory download
				s.console.PrintlnDebugStep("Downloading directory %s to %s", remotePath, localPath)

				// Create base directory
				err = ensureLocalDir(localPath)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to create local directory: %v", err)
					continue
				}

				// Count files for progress reporting
				fileCount := 0
				totalSize := int64(0)
				processingError := false

				// First pass: count files and total size
				err = s.walkRemoteDir(sftpClient, remotePath, "", func(remotePath, localRelPath string, isDir bool) error {
					if !isDir {
						fileCount++
						fi, err := sftpClient.Stat(remotePath)
						if err != nil {
							return err
						}
						totalSize += fi.Size()
					}
					return nil
				})

				if err != nil {
					s.console.PrintlnErrorStep("Error scanning directory: %v", err)
					continue
				}

				s.console.PrintlnDebugStep("Found %d files totaling %.2f MB", fileCount, float64(totalSize)/(1024*1024))

				// Second pass: download files
				currentFile := 0
				downloadedSize := int64(0)

				err = s.walkRemoteDir(sftpClient, remotePath, "", func(remotePath, localRelPath string, isDir bool) error {
					localFullPath := filepath.Join(localPath, localRelPath)

					if isDir {
						// Create directory
						return ensureLocalDir(localFullPath)
					} else {
						// Download file
						currentFile++
						s.console.PrintlnDebugStep("Downloading file %d/%d: %s", currentFile, fileCount, remotePath)

						// Open remote file
						rFile, err := sftpClient.Open(remotePath)
						if err != nil {
							return fmt.Errorf("failed to open remote file: %v", err)
						}
						defer rFile.Close()

						// Get file size
						fi, err := sftpClient.Stat(remotePath)
						if err != nil {
							return fmt.Errorf("failed to get remote file info: %v", err)
						}
						fileSize := fi.Size()

						// Create local file
						lFile, err := os.Create(localFullPath)
						if err != nil {
							return fmt.Errorf("failed to create local file: %v", err)
						}
						defer lFile.Close()

						// Copy file with progress
						bytesWritten, err := s.copyFileWithProgress(rFile, lFile, remotePath, localFullPath, fileSize, fmt.Sprintf("Download (%d/%d)", currentFile, fileCount))
						if err != nil {
							return fmt.Errorf("failed to copy file: %v", err)
						}

						downloadedSize += bytesWritten
						return nil
					}
				})

				if err != nil {
					s.console.PrintlnErrorStep("Error during download: %v", err)
					processingError = true
				}

				if !processingError {
					s.console.PrintlnOkStep("Downloaded directory %s to %s (%d files, %.2f MB)",
						remotePath,
						localPath,
						fileCount,
						float64(downloadedSize)/(1024*1024))
				}
			} else {
				// Single file download
				s.console.PrintlnDebugStep("Downloading file %s to %s (%.2f KB)", remotePath, localPath, float64(fi.Size())/1024.0)

				// Open remote file
				rFile, err := sftpClient.Open(remotePath)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to open remote file: %v", err)
					continue
				}
				defer rFile.Close()

				// Create local file
				lFile, err := os.Create(localPath)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to create local file: %v", err)
					continue
				}
				defer lFile.Close()

				// Copy file with progress
				_, err = s.copyFileWithProgress(rFile, lFile, remotePath, localPath, fi.Size(), "Download")
				if err != nil {
					s.console.PrintlnErrorStep("Failed to download file: %v", err)
				}
			}

		case "put", "upload":
			// Upload a file from server to client
			recursive := false
			args = s.parseRecursiveFlag(args, &recursive)

			if len(args) < 1 {
				s.console.PrintlnErrorStep("Usage: put [-r] <local_path> [remote_path]")
				s.console.PrintlnDebugStep("  -r: Upload directories recursively")
				continue
			}

			// Process local path
			localPath := args[0]

			// Get local file info to check if it exists
			fi, err := os.Stat(localPath)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to access local path: %v", err)
				continue
			}

			// Determine remote path
			remotePath := filepath.Base(localPath)
			if len(args) > 1 {
				remotePath = args[1]
			}

			// If remote path is not absolute, join with current working directory
			if !filepath.IsAbs(remotePath) {
				remotePath = filepath.Join(remoteCwd, remotePath)
			}

			// Handle differently based on whether it's a directory or file
			if fi.IsDir() {
				if !recursive {
					s.console.PrintlnErrorStep("Cannot upload a directory without -r flag")
					continue
				}

				// Recursive directory upload
				s.console.PrintlnDebugStep("Uploading directory %s to %s", localPath, remotePath)

				// Create base directory on remote
				err = ensureRemoteDir(sftpClient, remotePath)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to create remote directory: %v", err)
					continue
				}

				// Count files for progress reporting
				fileCount := 0
				totalSize := int64(0)
				processingError := false

				// First pass: count files and total size
				err = s.walkLocalDir(localPath, "", func(localPath, remoteRelPath string, isDir bool) error {
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

				if err != nil {
					s.console.PrintlnErrorStep("Error scanning directory: %v", err)
					continue
				}

				s.console.PrintlnDebugStep("Found %d files totaling %.2f MB", fileCount, float64(totalSize)/(1024*1024))

				// Second pass: upload files
				currentFile := 0
				uploadedSize := int64(0)

				err = s.walkLocalDir(localPath, "", func(localPath, remoteRelPath string, isDir bool) error {
					remoteFullPath := filepath.Join(remotePath, remoteRelPath)

					if isDir {
						// Create directory
						return ensureRemoteDir(sftpClient, remoteFullPath)
					} else {
						// Upload file
						currentFile++
						s.console.PrintlnDebugStep("Uploading file %d/%d: %s", currentFile, fileCount, localPath)

						// Open local file
						lFile, err := os.Open(localPath)
						if err != nil {
							return fmt.Errorf("failed to open local file: %v", err)
						}
						defer lFile.Close()

						// Get file size
						fi, err := os.Stat(localPath)
						if err != nil {
							return fmt.Errorf("failed to get local file info: %v", err)
						}
						fileSize := fi.Size()

						// Create remote file
						rFile, err := sftpClient.Create(remoteFullPath)
						if err != nil {
							return fmt.Errorf("failed to create remote file: %v", err)
						}
						defer rFile.Close()

						// Copy file with progress
						bytesWritten, err := s.copyFileWithProgress(lFile, rFile, localPath, remoteFullPath, fileSize, fmt.Sprintf("Upload (%d/%d)", currentFile, fileCount))
						if err != nil {
							return fmt.Errorf("failed to copy file: %v", err)
						}

						uploadedSize += bytesWritten
						return nil
					}
				})

				if err != nil {
					s.console.PrintlnErrorStep("Error during upload: %v", err)
					processingError = true
				}

				if !processingError {
					s.console.PrintlnOkStep("Uploaded directory %s to %s (%d files, %.2f MB)",
						localPath,
						remotePath,
						fileCount,
						float64(uploadedSize)/(1024*1024))
				}
			} else {
				// Single file upload
				fileSize := fi.Size()
				s.console.PrintlnDebugStep("Uploading file %s to %s (%.2f KB)", localPath, remotePath, float64(fileSize)/1024.0)

				// Open local file
				lFile, err := os.Open(localPath)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to open local file: %v", err)
					continue
				}
				defer lFile.Close()

				// Create remote file
				rFile, err := sftpClient.Create(remotePath)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to create remote file: %v", err)
					continue
				}
				defer rFile.Close()

				// Copy file with progress
				_, err = s.copyFileWithProgress(lFile, rFile, localPath, remotePath, fileSize, "Upload")
				if err != nil {
					s.console.PrintlnErrorStep("Failed to upload file: %v", err)
				}
			}

		case "mkdir":
			// Create directory
			if len(args) < 1 {
				s.console.PrintlnErrorStep("Usage: mkdir <directory>")
				continue
			}

			// Process directory path
			dirPath := args[0]
			if !filepath.IsAbs(dirPath) {
				dirPath = filepath.Join(remoteCwd, dirPath)
			}

			// Check if the directory already exists
			_, err := sftpClient.Stat(dirPath)
			if err == nil {
				s.console.PrintlnErrorStep("Directory or file already exists: %s", dirPath)
				continue
			}

			// Create the directory
			err = sftpClient.Mkdir(dirPath)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to create directory: %v", err)
				continue
			}

			s.console.PrintlnOkStep("Created directory: %s", dirPath)

		case "rm", "del", "delete":
			// Remove file or directory
			recursive := false
			args = s.parseRecursiveFlag(args, &recursive)

			if len(args) < 1 {
				s.console.PrintlnErrorStep("Usage: rm [-r] <path>")
				s.console.PrintlnDebugStep("  -r: Remove directories and their contents recursively")
				continue
			}

			// Process path
			path := args[0]
			if !filepath.IsAbs(path) {
				path = filepath.Join(remoteCwd, path)
			}

			// Check if path exists
			fi, err := sftpClient.Stat(path)
			if err != nil {
				s.console.PrintlnErrorStep("File or directory not found: %v", err)
				continue
			}

			if fi.IsDir() {
				// It's a directory
				if recursive {
					// Count items for reporting
					fileCount := 0
					dirCount := 0

					// First pass: count files and directories
					err = s.walkRemoteDir(sftpClient, path, "", func(remotePath, localRelPath string, isDir bool) error {
						if isDir {
							dirCount++
						} else {
							fileCount++
						}
						return nil
					})

					if err != nil {
						s.console.PrintlnErrorStep("Error scanning directory: %v", err)
						continue
					}

					// Confirm deletion with user
					s.console.PrintlnDebugStep("Will delete %d files and %d directories. Proceed? (y/n)", fileCount, dirCount)
					confirmation, err := s.console.Term.ReadLine()
					if err != nil || strings.ToLower(confirmation) != "y" {
						s.console.PrintlnDebugStep("Deletion cancelled")
						continue
					}

					// Perform recursive removal
					err = s.removeDirectoryRecursive(sftpClient, path)
					if err != nil {
						s.console.PrintlnErrorStep("Failed to remove directory recursively: %v", err)
						continue
					}
					s.console.PrintlnOkStep("Removed directory %s and its contents (%d files, %d directories)", path, fileCount, dirCount)
				} else {
					// Try to remove empty directory
					err = sftpClient.RemoveDirectory(path)
					if err != nil {
						s.console.PrintlnErrorStep("Failed to remove directory (might not be empty, use -r flag): %v", err)
						continue
					}
					s.console.PrintlnOkStep("Removed directory: %s", path)
				}
			} else {
				// It's a file
				err = sftpClient.Remove(path)
				if err != nil {
					s.console.PrintlnErrorStep("Failed to remove file: %v", err)
					continue
				}
				s.console.PrintlnOkStep("Removed file: %s", path)
			}

		case "chmod":
			// Change file permissions
			if len(args) < 2 {
				s.console.PrintlnErrorStep("Usage: chmod <permissions> <file>")
				s.console.PrintlnDebugStep("  permissions: numeric mode (e.g., 0755)")
				continue
			}

			// Parse permissions
			modeStr := args[0]
			path := args[1]

			// Handle relative path
			if !filepath.IsAbs(path) {
				path = filepath.Join(remoteCwd, path)
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
				s.console.PrintlnErrorStep("Invalid permission format (use octal, e.g., 0755): %v", err)
				continue
			}

			// Check if file exists
			_, err = sftpClient.Stat(path)
			if err != nil {
				s.console.PrintlnErrorStep("File or directory not found: %v", err)
				continue
			}

			// Change permissions
			err = sftpClient.Chmod(path, os.FileMode(mode))
			if err != nil {
				s.console.PrintlnErrorStep("Failed to change permissions: %v", err)
				continue
			}

			s.console.PrintlnOkStep("Changed permissions of %s to %s (%s)",
				path,
				modeStr,
				os.FileMode(mode).String())

		case "stat", "info":
			// Display file information
			if len(args) < 1 {
				s.console.PrintlnErrorStep("Usage: stat <file_or_directory>")
				continue
			}

			// Process path
			path := args[0]
			if !filepath.IsAbs(path) {
				path = filepath.Join(remoteCwd, path)
			}

			// Get file info
			fi, err := sftpClient.Stat(path)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to get file information: %v", err)
				continue
			}

			// Create formatted display
			tw := new(tabwriter.Writer)
			tw.Init(s.console.Term, 0, 4, 2, ' ', 0)

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
			_, _ = fmt.Fprintf(tw, "\nFile Information for: %s\n\n", path)
			_, _ = fmt.Fprintf(tw, "Name:\t%s\n", filepath.Base(path))
			_, _ = fmt.Fprintf(tw, "Type:\t%s\n", fileType)
			_, _ = fmt.Fprintf(tw, "Size:\t%s\n", sizeStr)
			_, _ = fmt.Fprintf(tw, "Permissions:\t%s (%04o)\n", fi.Mode().String(), fi.Mode().Perm())
			_, _ = fmt.Fprintf(tw, "Modified:\t%s\n", fi.ModTime().Format("Jan 02, 2006 15:04:05 MST"))

			// Try to get extended information
			if sftpStat, ok := fi.Sys().(*sftp.FileStat); ok {
				// If we can access the underlying FileStat struct
				_, _ = fmt.Fprintf(tw, "Owner UID:\t%d\n", sftpStat.UID)
				_, _ = fmt.Fprintf(tw, "Group GID:\t%d\n", sftpStat.GID)
			}

			_ = tw.Flush()

		case "rename", "mv", "move":
			// Rename file or directory
			if len(args) < 2 {
				s.console.PrintlnErrorStep("Usage: rename <source> <destination>")
				continue
			}

			// Process paths
			srcPath := args[0]
			dstPath := args[1]

			// Handle relative paths
			if !filepath.IsAbs(srcPath) {
				srcPath = filepath.Join(remoteCwd, srcPath)
			}
			if !filepath.IsAbs(dstPath) {
				dstPath = filepath.Join(remoteCwd, dstPath)
			}

			// Check if source exists
			srcFi, err := sftpClient.Stat(srcPath)
			if err != nil {
				s.console.PrintlnErrorStep("Source file or directory not found: %v", err)
				continue
			}

			// Check if destination already exists
			_, err = sftpClient.Stat(dstPath)
			if err == nil {
				s.console.PrintlnErrorStep("Destination already exists, cannot overwrite")
				continue
			}

			// Rename file or directory
			err = sftpClient.Rename(srcPath, dstPath)
			if err != nil {
				s.console.PrintlnErrorStep("Failed to rename: %v", err)
				continue
			}

			if srcFi.IsDir() {
				s.console.PrintlnOkStep("Renamed directory from %s to %s", srcPath, dstPath)
			} else {
				s.console.PrintlnOkStep("Renamed file from %s to %s", srcPath, dstPath)
			}

		case "exit", "quit":
			// Exit SFTP session
			s.console.PrintlnDebugStep("Exiting SFTP session")
			return

		default:
			s.console.PrintlnErrorStep("Unknown command: %s", command)
			s.console.PrintlnDebugStep("Type 'help' for available commands")
		}
	}
}

// printSFTPHelp displays available SFTP commands
func (s *server) printSFTPHelp() {
	tw := new(tabwriter.Writer)
	tw.Init(s.console.Term, 0, 4, 2, ' ', 0)

	_, _ = fmt.Fprintf(tw, "\n\tCommand\tDescription\t\n")
	_, _ = fmt.Fprintf(tw, "\t-------\t-----------\t\n")

	// Directory navigation commands
	_, _ = fmt.Fprintf(tw, "\tpwd, getwd\tShow current remote directory\t\n")
	_, _ = fmt.Fprintf(tw, "\tls, dir, list [path]\tList directory contents\t\n")
	_, _ = fmt.Fprintf(tw, "\tcd, chdir [dir]\tChange directory (use .. for parent, no args for root)\t\n")

	// File operations
	_, _ = fmt.Fprintf(tw, "\tget, download [-r] <remote> [local]\tDownload file or directory (-r for recursive)\t\n")
	_, _ = fmt.Fprintf(tw, "\tput, upload [-r] <local> [remote]\tUpload file or directory (-r for recursive)\t\n")
	_, _ = fmt.Fprintf(tw, "\tmkdir <dir>\tCreate directory\t\n")
	_, _ = fmt.Fprintf(tw, "\trm, del, delete [-r] <path>\tRemove file or directory (-r for recursive deletion)\t\n")

	// File attributes and information
	_, _ = fmt.Fprintf(tw, "\tchmod <mode> <path>\tChange file permissions (e.g., chmod 0755 file.txt)\t\n")
	_, _ = fmt.Fprintf(tw, "\tstat, info <path>\tShow detailed file information\t\n")
	_, _ = fmt.Fprintf(tw, "\trename, mv, move <src> <dst>\tRename or move a file or directory\t\n")

	// General commands
	_, _ = fmt.Fprintf(tw, "\thelp\tShow this help\t\n")
	_, _ = fmt.Fprintf(tw, "\texit, quit\tExit SFTP session\t\n")

	_, _ = fmt.Fprintln(tw)
	_ = tw.Flush()
}

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
					ftp.console.Printf("\r%s %s %.1f%% (%.1f/%.1f MB) %s    ",
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
func (s *server) removeDirectoryRecursive(client *sftp.Client, dirPath string) error {
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
			err = s.removeDirectoryRecursive(client, path)
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
func (s *server) walkLocalDir(basePath, relativePath string, callback func(localPath, remotePath string, isDir bool) error) error {
	fullPath := filepath.Join(basePath, relativePath)

	// Get file info
	fileInfo, err := os.Stat(fullPath)
	if err != nil {
		return fmt.Errorf("failed to access path %s: %v", fullPath, err)
	}

	// Calculate the remote path (preserve directory structure)
	remotePath := relativePath
	if remotePath == "" {
		remotePath = filepath.Base(basePath)
	}

	// Process the current item
	err = callback(fullPath, remotePath, fileInfo.IsDir())
	if err != nil {
		return err
	}

	// If it's a directory, process its contents
	if fileInfo.IsDir() {
		entries, err := os.ReadDir(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read directory %s: %v", fullPath, err)
		}

		for _, entry := range entries {
			entryRelPath := filepath.Join(relativePath, entry.Name())
			err = s.walkLocalDir(basePath, entryRelPath, callback)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// walkRemoteDir recursively walks a remote directory via SFTP for download operations
func (s *server) walkRemoteDir(sftpClient *sftp.Client, basePath, relativePath string, callback func(remotePath, localPath string, isDir bool) error) error {
	fullPath := filepath.Join(basePath, relativePath)

	// Get file info
	fileInfo, err := sftpClient.Stat(fullPath)
	if err != nil {
		return fmt.Errorf("failed to access remote path %s: %v", fullPath, err)
	}

	// Calculate the local path (preserve directory structure)
	localPath := relativePath
	if localPath == "" {
		localPath = filepath.Base(basePath)
	}

	// Process the current item
	err = callback(fullPath, localPath, fileInfo.IsDir())
	if err != nil {
		return err
	}

	// If it's a directory, process its contents
	if fileInfo.IsDir() {
		entries, err := sftpClient.ReadDir(fullPath)
		if err != nil {
			return fmt.Errorf("failed to read remote directory %s: %v", fullPath, err)
		}

		for _, entry := range entries {
			entryRelPath := filepath.Join(relativePath, entry.Name())
			err = s.walkRemoteDir(sftpClient, basePath, entryRelPath, callback)
			if err != nil {
				return err
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
func (s *server) copyFileWithProgress(src io.Reader, dst io.Writer, srcName, dstName string, size int64, operation string) (int64, error) {
	return CopyWithProgress(dst, src, s.console, srcName, dstName, size, operation)
}

// parseRecursiveFlag checks for -r flag in args and returns the args without the flag
func (s *server) parseRecursiveFlag(args []string, recursive *bool) []string {
	if len(args) > 0 && (args[0] == "-r" || args[0] == "--recursive") {
		*recursive = true
		return args[1:]
	}
	return args
}
