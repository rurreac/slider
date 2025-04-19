package server

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/sflag"
	"slider/pkg/slog"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	serverUsage = "\n\rSlider Server" +
		"\n\n\r  Creates a new Slider Server instance and waits for" +
		"\n\rincoming Slider Client connections on the defined port." +
		"\n\n\r  Interaction with Slider Clients can be performed through" +
		"\n\rits integrated Console by pressing CTR^C at any time." +
		"\r\n\nUsage: <slider_server> [flags]"

	clientCertsFile = "client-certs.json"
	serverCertFile  = "server-cert.json"
)

// sessionTrack keeps track of sessions and clients
type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
}

type server struct {
	*slog.Logger
	sshConf              *ssh.ServerConfig
	sessionTrack         *sessionTrack
	sessionTrackMutex    sync.Mutex
	console              Console
	serverInterpreter    *interpreter.Interpreter
	certTrack            *scrypt.CertTrack
	certTrackMutex       sync.Mutex
	certJarFile          string
	authOn               bool
	certSaveOn           bool
	keepalive            time.Duration
	urlRedirect          *url.URL
	templatePath         string
	serverHeader         string
	statusCode           int
	serverKey            ssh.Signer
	httpVersion          bool
	httpHealth           bool
	CertificateAuthority *scrypt.CertificateAuthority
}

func NewServer(args []string) {
	serverFlags := sflag.NewFlagPack([]string{"server"}, serverUsage, "", os.Stdout)
	verbose, _ := serverFlags.NewStringFlag("", "verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	address, _ := serverFlags.NewStringFlag("", "address", "0.0.0.0", "Server will bind to this address")
	port, _ := serverFlags.NewIntFlag("", "port", 8080, "port where Server will listen")
	keepalive, _ := serverFlags.NewDurationFlag("", "keepalive", conf.Keepalive, "Sets keepalive interval vs Clients")
	colorless, _ := serverFlags.NewBoolFlag("", "colorless", false, "Disables logging colors")
	auth, _ := serverFlags.NewBoolFlag("", "auth", false, "Enables Key authentication of Clients")
	certJarFile, _ := serverFlags.NewStringFlag("", "certs", "", "Path of a valid slider-certs json file")
	keyStore, _ := serverFlags.NewBoolFlag("", "keystore", false, "Store Server key for later use")
	keyPath, _ := serverFlags.NewStringFlag("", "keypath", "", "Path for reading and/or storing a Server key")
	templatePath, _ := serverFlags.NewStringFlag("", "http-template", "", "Path of a default file to serve")
	serverHeader, _ := serverFlags.NewStringFlag("", "http-server-header", "", "Sets a server header value")
	httpRedirect, _ := serverFlags.NewStringFlag("", "http-redirect", "", "Redirects incoming HTTP to given URL")
	statusCode, _ := serverFlags.NewIntFlag("", "http-status-code", 200, "Status code [200|301|302|400|401|403|500|502|503]")
	httpVersion, _ := serverFlags.NewBoolFlag("", "http-version", false, "Enables /version HTTP path")
	httpHealth, _ := serverFlags.NewBoolFlag("", "http-health", false, "Enables /health HTTP path")
	serverFlags.Set.Usage = func() {
		serverFlags.PrintUsage(false)
	}

	if pErr := serverFlags.Parse(args); pErr != nil {
		if fmt.Sprintf("%v", pErr) == "flag: help requested" {
			return
		}
		fmt.Printf("Flag error: %v\n", pErr)
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
		console: Console{FirstRun: true},
		certTrack: &scrypt.CertTrack{
			Certs: make(map[int64]*scrypt.KeyPair),
		},
		certJarFile:  *certJarFile,
		authOn:       *auth,
		urlRedirect:  &url.URL{},
		serverHeader: *serverHeader,
		httpVersion:  *httpVersion,
		httpHealth:   *httpHealth,
	}

	if *templatePath != "" {
		tErr := conf.CheckTemplate(*templatePath)
		if tErr != nil {
			s.Logger.Fatalf("Wrong template: %s", tErr)
		}
		s.templatePath = *templatePath
	}

	s.statusCode = *statusCode
	if !conf.CheckStatusCode(*statusCode) {
		s.Logger.Warnf("Invalid status code \"%d\", will use \"%d\"", *statusCode, http.StatusOK)
		s.statusCode = http.StatusOK
	}

	// Ensure a minimum keepalive
	if *keepalive < conf.MinKeepAlive {
		s.Logger.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		*keepalive = conf.MinKeepAlive
	}
	s.keepalive = *keepalive

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		s.Logger.Fatalf("%v", iErr)
	}
	s.serverInterpreter = i

	//var signer ssh.Signer
	var prErr error
	var kErr error
	var serverKeyPair *scrypt.ServerKeyPair
	var privateKeySigner ssh.Signer
	if *keyStore || *keyPath != "" {
		kp := conf.GetSliderHome() + serverCertFile

		if *keyPath != "" {
			kp = *keyPath
		}

		if _, sErr := os.Stat(kp); os.IsNotExist(sErr) && !*keyStore && *keyPath != "" {
			s.Logger.Fatalf("Failed load Server Key, %s does not exist", kp)
		} else if os.IsNotExist(sErr) && *keyStore {
			s.Logger.Debugf("Storing New Server Certificate on %s", kp)
		} else {
			s.Logger.Infof("Importing existing Server Certificate from %s", kp)
		}

		serverKeyPair, kErr = scrypt.ServerKeyPairFromFile(kp)
		if kErr != nil {
			s.Logger.Fatalf("Failed to load Server Key: %v", kErr)
		}
		privateKeySigner, prErr = scrypt.SignerFromKey(serverKeyPair.PrivateKey)
		if prErr != nil {
			s.Logger.Fatalf("Failed generate SSH signer: %v", prErr)
		}
	} else {
		serverKeyPair, kErr = scrypt.NewServerKeyPair()
		if kErr != nil {
			s.Logger.Fatalf("Failed to generate Server Key: %v", kErr)
		}
		privateKeySigner, prErr = scrypt.SignerFromKey(serverKeyPair.PrivateKey)
		if prErr != nil {
			s.Logger.Fatalf("failed to create signer: %v", prErr)
		}

	}
	s.serverKey = privateKeySigner
	s.CertificateAuthority = serverKeyPair.CertificateAuthority
	s.sshConf.AddHostKey(s.serverKey)

	serverFp, fErr := scrypt.GenerateFingerprint(s.serverKey.PublicKey())
	if fErr != nil {
		s.Logger.Fatalf("Failed to generate server fingerprint")
	}
	s.Logger.Infof("Server Fingerprint: %s", serverFp)

	if *auth {
		s.Logger.Warnf("Client Authentication enabled, a valid certificate will be required")

		if s.certJarFile == "" {
			s.certJarFile = conf.GetSliderHome() + clientCertsFile
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

	if *httpRedirect != "" {
		wr, wErr := conf.ResolveURL(*httpRedirect)
		if wErr != nil {
			s.Logger.Fatalf("Bad Redirect URL: %v", wErr)
		}
		s.urlRedirect = wr
		s.Logger.Debugf("Redirecting incomming HTTP requests to \"%s\"", s.urlRedirect)
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

	// Capture Interrupt Signal to toggle log output and activate Console
	s.Logger.Infof("Press CTR^C to access the Slider Console")
	var cmdOutput string
	for consoleToggle := true; consoleToggle; {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		for range sig {
			// Stop capturing so we can capture as well on the console
			signal.Stop(sig)
			close(sig)
			// Send logs to a buffer
			s.Logger.LogToBuffer()
			// Run a Slider Console (NewConsole locks until termination),
			// 'cmdOutput' will always be equal to "bg" or "exit"
			cmdOutput = s.NewConsole()
			// Restore logs from buffer and resume output to stdout
			s.Logger.BufferOut()
			s.Logger.LogToStdout()
		}
		if cmdOutput == "exit" {
			consoleToggle = false
		}
	}

	s.Logger.Printf("Server down...")
}

func (s *server) clientVerification(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fp, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return nil, fmt.Errorf("failed to generate fingerprint from public key - %s", fErr)
	}

	if id, ok := scrypt.IsAllowedFingerprint(fp, s.certTrack.Certs); ok {
		s.Logger.Debugf("Authenticated Client %s fingerprint: %s", conn.RemoteAddr(), fp)
		return &ssh.Permissions{
			Extensions: map[string]string{
				"fingerprint": fp,
				"cert_id":     fmt.Sprintf("%d", id),
			},
		}, nil
	}
	s.Logger.Warnf("Rejected client %s, due to bad key authentication", conn.RemoteAddr())

	return nil, fmt.Errorf("client key not authorized")
}
