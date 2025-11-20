package server

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/scrypt"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// ServerConfig holds all configuration for a server instance
type ServerConfig struct {
	Verbose      string
	Address      string
	Port         int
	Keepalive    time.Duration
	Colorless    bool
	Auth         bool
	CertJarFile  string
	CaStore      bool
	CaStorePath  string
	TemplatePath string
	ServerHeader string
	HttpRedirect string
	StatusCode   int
	HttpVersion  bool
	HttpHealth   bool
	CustomProto  string
	ListenerCert string
	ListenerKey  string
	ListenerCA   string
}

// RunServer starts a server with the given configuration
func RunServer(cfg *ServerConfig) {
	sshConf := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-slider-server",
	}

	log := slog.NewLogger("Server")
	lvErr := log.SetLevel(cfg.Verbose)
	if lvErr != nil {
		fmt.Printf("wrong log level \"%s\", %v", cfg.Verbose, lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if interpreter.IsPtyOn() && !cfg.Colorless {
		log.WithColors()
	}

	s := &server{
		Logger: log,
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*Session),
		},
		sshConf: sshConf,
		console: Console{
			FirstRun: true,
			History: &CustomHistory{
				entries: make([]string, 0),
				maxSize: 100,
			},
		},
		certTrack: &scrypt.CertTrack{
			Certs: make(map[int64]*scrypt.KeyPair),
		},
		certJarFile:  cfg.CertJarFile,
		authOn:       cfg.Auth,
		caStoreOn:    cfg.CaStore,
		urlRedirect:  &url.URL{},
		serverHeader: cfg.ServerHeader,
		httpVersion:  cfg.HttpVersion,
		httpHealth:   cfg.HttpHealth,
		customProto:  cfg.CustomProto,
	}

	if cfg.TemplatePath != "" {
		tErr := conf.CheckTemplate(cfg.TemplatePath)
		if tErr != nil {
			s.Logger.Fatalf("Wrong template: %s", tErr)
		}
		s.templatePath = cfg.TemplatePath
	}

	s.statusCode = cfg.StatusCode
	if !conf.CheckStatusCode(cfg.StatusCode) {
		s.Logger.Warnf("Invalid status code \"%d\", will use \"%d\"", cfg.StatusCode, http.StatusOK)
		s.statusCode = http.StatusOK
	}

	// Ensure a minimum keepalive
	if cfg.Keepalive < conf.MinKeepAlive {
		s.Logger.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		cfg.Keepalive = conf.MinKeepAlive
	}
	s.keepalive = cfg.Keepalive

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		s.Logger.Fatalf("%v", iErr)
	}
	s.serverInterpreter = i

	var prErr error
	var kErr error
	var serverKeyPair *scrypt.ServerKeyPair
	var privateKeySigner ssh.Signer
	if cfg.CaStore || cfg.CaStorePath != "" {
		kp := conf.GetSliderHome() + serverCertFile

		if cfg.CaStorePath != "" {
			kp = cfg.CaStorePath
		}

		if _, sErr := os.Stat(kp); os.IsNotExist(sErr) && !cfg.CaStore && cfg.CaStorePath != "" {
			s.Logger.Fatalf("Failed load Server Key, %s does not exist", kp)
		} else if os.IsNotExist(sErr) && cfg.CaStore {
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

	if cfg.Auth {
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

	if cfg.HttpRedirect != "" {
		wr, wErr := conf.ResolveURL(cfg.HttpRedirect)
		if wErr != nil {
			s.Logger.Fatalf("Bad Redirect URL: %v", wErr)
		}
		s.urlRedirect = wr
		s.Logger.Debugf("Redirecting incomming HTTP requests to \"%s\"", s.urlRedirect)
	}

	fmtAddress := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	serverAddr, rErr := net.ResolveTCPAddr("tcp", fmtAddress)
	if rErr != nil {
		s.Logger.Fatalf("Not a valid IP address \"%s\"", fmtAddress)
	}

	tlsOn := false
	tlsConfig := &tls.Config{}
	listenerProto := "tcp"
	if cfg.ListenerCert != "" && cfg.ListenerKey != "" {
		tlsOn = true
		listenerProto = "tls"
		if cfg.ListenerCA != "" {
			s.Logger.Warnf("Using CA \"%s\" for TLS client verification", cfg.ListenerCA)
			caPem, rfErr := os.ReadFile(cfg.ListenerCA)
			if rfErr != nil {
				s.Logger.Fatalf("Failed to read CA file: %v", rfErr)
			}
			if len(caPem) == 0 {
				s.Logger.Fatalf("CA file is empty")
			}
			tlsConfig = scrypt.GetTLSClientVerifiedConfig(caPem)
		}
	}

	s.Logger.Infof("Starting listener %s://%s", listenerProto, serverAddr.String())
	go func() {
		handler := http.Handler(http.HandlerFunc(s.handleHTTPClient))

		if tlsOn {
			httpSrv := &http.Server{
				Addr:      serverAddr.String(),
				TLSConfig: tlsConfig,
				ErrorLog:  slog.NewDummyLog(),
			}
			httpSrv.Handler = handler
			if sErr := httpSrv.ListenAndServeTLS(cfg.ListenerCert, cfg.ListenerKey); sErr != nil {
				s.Logger.Fatalf("TLS Listener error: %s", sErr)
			}
			return
		}
		if sErr := http.ListenAndServe(serverAddr.String(), handler); sErr != nil {
			s.Logger.Fatalf("Listener error: %s", sErr)
		}
	}()

	s.Logger.Infof("Press CTR^C to access the Slider Console")

	// Capture Interrupt Signal to toggle log output and activate Console
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
