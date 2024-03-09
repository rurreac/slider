package server

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// config creates the server configuration build from flags
type config struct {
	keyGen    bool
	keyFile   string
	authFile  string
	addr      address
	timeout   time.Duration
	keepalive time.Duration
}

type address struct {
	host string
	port string
}

// sessionTrack keeps track of sessions and clients
type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
}

type server struct {
	*slog.Logger
	conf              *config
	sshConf           *ssh.ServerConfig
	sessionTrack      *sessionTrack
	sessionTrackMutex sync.Mutex
	console           Console
	ServerInterpreter *interpreter.Interpreter
}

func NewServer(args []string) {
	serverFlags := flag.NewFlagSet("server", flag.ContinueOnError)
	verbose := serverFlags.String("verbose", "INFO", "Adds verbosity [debug|info|warn|error]")
	ip := serverFlags.String("address", "0.0.0.0", "Server will bind to this address")
	port := serverFlags.String("port", "8080", "Port where Server will listen")
	keepalive := serverFlags.Duration("keepalive", 60*time.Second, "Set keepalive interval vs clients")
	colorless := serverFlags.Bool("colorless", false, "Disables logging colors")
	serverFlags.Usage = func() {
		fmt.Printf(serverHelpLong)
		serverFlags.PrintDefaults()
		fmt.Println()
	}
	if fErr := serverFlags.Parse(args); fErr != nil {
		return
	}

	if slices.Contains(args, "help") {
		serverFlags.Usage()
		return
	}

	conf := &config{
		addr: address{
			host: *ip,
			port: *port,
		},
		keepalive: *keepalive,
		keyGen:    false,
	}

	sshConf := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-slider-server",
	}

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		panic(iErr)
	}

	log := slog.NewLogger("Server")
	if lvErr := log.SetLevel(*verbose); lvErr != nil {
		fmt.Printf("%v", lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if i.PtyOn && !*colorless {
		log.WithColors()
	}

	s := &server{
		conf:   conf,
		Logger: log,
		sessionTrack: &sessionTrack{
			SessionCount:  0,
			SessionActive: 0,
			Sessions:      make(map[int64]*Session),
		},
		sshConf:           sshConf,
		console:           Console{},
		ServerInterpreter: i,
	}

	signer, err := scrypt.GenerateEd25519Key()
	if err != nil {
		panic(err)
	}
	s.sshConf.AddHostKey(signer)

	l, lisErr := net.Listen(
		"tcp",
		fmt.Sprintf("%s:%s", s.conf.addr.host, s.conf.addr.port),
	)
	if lisErr != nil {
		s.Fatalf("listener: %s", err)

	}

	s.Infof("listening on %s://%s:%s", l.Addr().Network(), conf.addr.host, conf.addr.port)
	s.Infof("Press CTR^C to access the Slider Console")

	// Hold the execution until exit from the console
	wg := sync.WaitGroup{}
	wg.Add(1)

	// Capture Interrupt Signal to toggle log output and activate C2 Console
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for range sig {
			// Send logs to a buffer
			s.Logger.LogToBuffer()
			// Run a Slider Console (NewConsole locks until termination),
			// 'out' will always be equal to "bg" or "exit"
			out := s.NewConsole()
			// Restore logs from buffer and resume output to stdout
			s.Logger.BufferOut()
			s.Logger.LogToStdout()
			if out == "exit" {
				break
			}
		}
		wg.Done()
	}()
	go func() {
		// TODO: net/http serve has no support for timeouts
		handler := http.Handler(http.HandlerFunc(s.handleHTTPClient))
		if err = http.Serve(l, handler); err != nil {
			s.Fatalf("%s", err)
		}
	}()

	wg.Wait()
	s.Printf("Server down...")
}
