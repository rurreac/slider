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
	sshConf           *ssh.ServerConfig
	sessionTrack      *sessionTrack
	sessionTrackMutex sync.Mutex
	console           Console
	serverInterpreter *interpreter.Interpreter
	certTrack         *certTrack
	certTrackMutex    sync.Mutex
	certJarFile       string
	authOn            bool
	certSaveOn        bool
	keepalive         time.Duration
}

func NewServer(args []string) {
	serverFlags := flag.NewFlagSet("server", flag.ContinueOnError)
	verbose := serverFlags.String("verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	address := serverFlags.String("address", "0.0.0.0", "Server will bind to this address")
	port := serverFlags.Int("port", 8080, "Port where Server will listen")
	keepalive := serverFlags.Duration("keepalive", conf.Keepalive, "Sets keepalive interval vs Clients")
	colorless := serverFlags.Bool("colorless", false, "Disables logging colors")
	auth := serverFlags.Bool("auth", false, "Enables Key authentication of Clients")
	certJarFile := serverFlags.String("certs", "", "Path of a valid slider-certs json file")
	keyStore := serverFlags.Bool("keystore", false, "Store Server key for later use")
	keyPath := serverFlags.String("keypath", "", "Path for reading or storing a Server key")
	serverFlags.Usage = func() {
		fmt.Println(serverHelp)
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

	log := slog.NewLogger("Server")
	lvErr := log.SetLevel(*verbose)
	if lvErr != nil {
		fmt.Printf("wrong log level \"%s\", %v", *verbose, lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if interpreter.IsPtyOn() && !*colorless {
		log.WithColors()
	}

	s := &server{
		Logger: log,
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*Session),
		},
		sshConf: sshConf,
		console: Console{},
		certTrack: &certTrack{
			Certs: make(map[int64]*scrypt.KeyPair),
		},
		certJarFile: *certJarFile,
		authOn:      *auth,
	}

	// Ensure a minimum keepalive
	if *keepalive < conf.MinKeepAlive {
		s.Logger.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		*keepalive = conf.Keepalive
	}
	s.keepalive = *keepalive

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		s.Logger.Fatalf("%v", iErr)
	}
	s.serverInterpreter = i

	var signer ssh.Signer
	var keyErr error
	if *keyStore || *keyPath != "" {
		kp := sio.GetSliderHome() + serverCertFile

		if *keyPath != "" {
			kp = *keyPath
		}

		if _, sErr := os.Stat(kp); os.IsNotExist(sErr) && !*keyStore && *keyPath != "" {
			s.Logger.Fatalf("Failed load Server Key, %s does not exist", kp)
		} else if os.IsNotExist(sErr) && *keyStore {
			s.Logger.Debugf("Storing New Server Certificate on %s", kp)
		} else {
			s.Logger.Debugf("Importing existing Server Certificate from %s", kp)
		}

		signer, keyErr = scrypt.NewSSHSignerFromFile(kp)
	} else {
		signer, keyErr = scrypt.NewSSHSigner()
	}
	if keyErr != nil {
		s.Logger.Fatalf("%v", keyErr)
	}
	s.sshConf.AddHostKey(signer)
	serverFp, fErr := scrypt.GenerateFingerprint(signer.PublicKey())
	if fErr != nil {
		s.Logger.Fatalf("Failed to generate server fingerprint")
	}
	s.Logger.Infof("Server Fingerprint: %s", serverFp)

	if *auth {
		s.Logger.Warnf("Client Authentication enabled, a valid certificate will be required")

		if s.certJarFile == "" {
			s.certJarFile = sio.GetSliderHome() + clientCertsFile
		}
		if lcErr := s.loadCertJar(); lcErr != nil {
			s.Logger.Fatalf("%v", lcErr)
		}

		s.sshConf.NoClientAuth = false
		s.sshConf.PublicKeyCallback = s.clientVerification
	} else {
		if s.certJarFile != "" {
			s.Logger.Warnf("Client Authentication is disabled, Certs File %s will be ignored", s.certJarFile)
		}
	}

	fmtAddress := fmt.Sprintf("%s:%d", *address, *port)
	serverAddr, rErr := net.ResolveTCPAddr("tcp", fmtAddress)
	if rErr != nil {
		s.Logger.Fatalf("Not a valid IP address \"%s\"", fmtAddress)
	}

	go func() {
		handler := http.Handler(http.HandlerFunc(s.handleHTTPClient))
		if sErr := http.ListenAndServe(serverAddr.String(), handler); sErr != nil {
			s.Logger.Fatalf("%s", sErr)
		}
	}()
	s.Logger.Infof("Listening on %s://%s", serverAddr.Network(), serverAddr.String())

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
	s.Logger.Infof("Press CTR^C to access the Slider Console")
	wg.Wait()
	s.Logger.Printf("Server down...")
}

func (s *server) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if s.isAllowedFingerprint(fp) {
		s.Logger.Debugf("Authenticated Client %s fingerprint: %s", conn.RemoteAddr(), fp)
		return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp}}, nil
	}
	s.Logger.Warnf("Rejected client %s, due to bad key authentication", conn.RemoteAddr())

	return nil, fmt.Errorf("client key not authorized")
}
