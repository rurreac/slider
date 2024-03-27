package server

import (
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const clientCertsFile = "client-certs.json"
const serverCertFile = "server-cert.json"

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

type certTrack struct {
	CertCount  int64
	CertActive int64
	Certs      map[int64]*scrypt.KeyPair
}

type server struct {
	*slog.Logger
	addr              address
	sshConf           *ssh.ServerConfig
	sessionTrack      *sessionTrack
	sessionTrackMutex sync.Mutex
	console           Console
	ServerInterpreter *interpreter.Interpreter
	certTrack         *certTrack
	certTrackMutex    sync.Mutex
	certJarFile       string
	authOn            bool
	certSaveOn        bool
	keepalive         time.Duration
}

func NewServer(args []string) {
	serverFlags := flag.NewFlagSet("server", flag.ContinueOnError)
	verbose := serverFlags.String("verbose", "info", "Adds verbosity [debug|info|warn|error]")
	ip := serverFlags.String("address", "0.0.0.0", "Server will bind to this address")
	port := serverFlags.String("port", "8080", "Port where Server will listen")
	keepalive := serverFlags.Duration("keepalive", conf.Keepalive, "Sets keepalive interval vs Clients")
	colorless := serverFlags.Bool("colorless", false, "Disables logging colors")
	auth := serverFlags.Bool("auth", false, "Enables Key authentication of Clients")
	certJarFile := serverFlags.String("certs", "", "Path of a valid slider-certs json file")
	keyStore := serverFlags.Bool("keystore", false, "Store Server key for later use")
	keyPath := serverFlags.String("keypath", "", "Path for reading or storing a Server key")

	serverFlags.Usage = func() {
		fmt.Printf(serverHelp)
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

	sshConf := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-slider-server",
	}

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		panic(iErr)
	}

	log := slog.NewLogger("Server")
	lvErr := log.SetLevel(*verbose)
	if lvErr != nil {
		fmt.Printf("%v", lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if i.PtyOn && !*colorless {
		log.WithColors()
	}

	s := &server{
		addr: address{
			host: *ip,
			port: *port,
		},
		Logger: log,
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*Session),
		},
		sshConf:           sshConf,
		console:           Console{},
		ServerInterpreter: i,
		certTrack: &certTrack{
			Certs: make(map[int64]*scrypt.KeyPair),
		},
		certJarFile: *certJarFile,
		authOn:      *auth,
		keepalive:   *keepalive,
	}

	var signer ssh.Signer
	var keyErr error
	if *keyStore || *keyPath != "" {
		kp := sio.GetSliderHome() + serverCertFile

		if *keyPath != "" {
			kp = *keyPath
		}

		if _, sErr := os.Stat(kp); os.IsNotExist(sErr) && !*keyStore && *keyPath != "" {
			s.Fatalf("Failed load Server Key, %s does not exist", kp)
		} else if os.IsNotExist(sErr) && *keyStore {
			s.Infof("Storing New Server Certificate on %s", kp)
		} else {
			s.Infof("Importing existing Server Certificate from %s", kp)
		}

		signer, keyErr = scrypt.NewSSHSignerFromFile(kp)
	} else {
		signer, keyErr = scrypt.NewSSHSigner()
	}
	if keyErr != nil {
		s.Fatalf("%v", keyErr)
	}
	s.sshConf.AddHostKey(signer)

	if *auth {
		s.Warnf("Client Authentication enabled, a valid certificate will be required")

		if s.certJarFile == "" {
			s.certJarFile = sio.GetSliderHome() + clientCertsFile
		}
		if lcErr := s.loadCertJar(); lcErr != nil {
			s.Fatalf("%v", lcErr)
		}

		s.sshConf.NoClientAuth = false
		s.sshConf.PublicKeyCallback = s.clientVerification
	} else {
		if s.certJarFile != "" {
			s.Warnf("Client Authentication is disabled, Certs File %s will be ignored", s.certJarFile)
		}
	}

	fingerprint, gErr := scrypt.GenerateFingerprint(signer.PublicKey())
	if gErr != nil {
		s.Fatalf("Failed to generate fingerprint - %v", gErr)
	}
	s.Infof("Server Fingerprint: %s", fingerprint)

	l, lisErr := net.Listen(
		"tcp",
		fmt.Sprintf("%s:%s", s.addr.host, s.addr.port),
	)
	if lisErr != nil {
		s.Fatalf("Listener: %v", lisErr)

	}

	s.Infof("Listening on %s://%s:%s", l.Addr().Network(), s.addr.host, s.addr.port)
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
			s.LogToBuffer()
			// Run a Slider Console (NewConsole locks until termination),
			// 'out' will always be equal to "bg" or "exit"
			out := s.NewConsole()
			// Restore logs from buffer and resume output to stdout
			s.BufferOut()
			s.LogToStdout()
			if out == "exit" {
				break
			}
		}
		wg.Done()
	}()
	go func() {
		// TODO: net/http serve has no support for timeouts
		handler := http.Handler(http.HandlerFunc(s.handleHTTPClient))
		if sErr := http.Serve(l, handler); sErr != nil {
			s.Fatalf("%s", sErr)
		}
	}()

	wg.Wait()
	s.Printf("Server down...")
}

func (s *server) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if s.isAllowedFingerprint(fp) {
		s.Debugf("Authenticated Client %s fingerprint: %s", conn.RemoteAddr(), fp)
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}
	s.Warnf("Rejected client %s, due to bad key authentication", conn.RemoteAddr())

	return nil, fmt.Errorf("client key not authorized")
}
