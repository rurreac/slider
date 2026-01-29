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
	"slider/pkg/listener"
	"slider/pkg/scrypt"
	"slider/pkg/session"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// Config holds all configuration for a server instance
type Config struct {
	Verbose       string
	Address       string
	Port          int
	Keepalive     time.Duration
	Colorless     bool
	Auth          bool
	CertJarFile   string
	CaStore       bool
	CaStorePath   string
	TemplatePath  string
	ServerHeader  string
	HttpRedirect  string
	StatusCode    int
	HttpVersion   bool
	HttpHealth    bool
	CustomProto   string
	ListenerCert  string
	ListenerKey   string
	ListenerCA    string
	JsonLog       bool
	CallerLog     bool
	Headless      bool
	HttpConsole   bool
	Gateway       bool
	CallbackURL   string
	CallbackRetry bool
}

// RunServer starts a server with the given configuration
func RunServer(cfg *Config) {
	sshConf := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-slider-server",
	}

	log := slog.NewLogger("Server")

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		log.Fatalf("%v", iErr)
	}

	if cfg.JsonLog {
		log.WithJSON(true)
	} else {
		if i.ColorOn && !cfg.Colorless {
			log.WithColors(true)
		} else {
			log.WithColors(false)
		}
	}
	if cfg.CallerLog {
		log.WithCallerInfo(true)
	}
	lvErr := log.SetLevel(cfg.Verbose)
	if lvErr != nil {
		log.Fatalf("Wrong log level (%s): %v", cfg.Verbose, lvErr)
		return
	}

	s := &server{
		Logger: log,
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*session.BidirectionalSession),
		},
		remoteSessions: make(map[string]*RemoteSessionState),
		sshConf:        sshConf,
		console: Console{
			FirstRun: true,
			History:  session.DefaultHistory,
		},
		certTrack: &scrypt.CertTrack{
			Certs: make(map[int64]*scrypt.KeyPair),
		},
		certJarFile:       cfg.CertJarFile,
		authOn:            cfg.Auth,
		host:              cfg.Address,
		port:              cfg.Port,
		caStoreOn:         cfg.CaStore,
		urlRedirect:       &url.URL{},
		serverHeader:      cfg.ServerHeader,
		httpVersion:       cfg.HttpVersion,
		httpHealth:        cfg.HttpHealth,
		httpConsoleOn:     cfg.HttpConsole,
		customProto:       cfg.CustomProto,
		gateway:           cfg.Gateway,
		serverInterpreter: i,
	}

	// Prevent Interactive Console without finalizing if this is not supported
	if !s.serverInterpreter.PtyOn && !cfg.Headless {
		s.Warnf("This System does not support PTY, headless mode is enforced")
		cfg.Headless = true
	}

	// Set template path for HTML pages
	if cfg.TemplatePath != "" {
		tErr := listener.CheckTemplate(cfg.TemplatePath)
		if tErr != nil {
			s.Fatalf("Wrong template: %s", tErr)
		}
		s.templatePath = cfg.TemplatePath
	} else {
		// Default to ./templates directory
		s.templatePath = "templates"
	}

	s.statusCode = cfg.StatusCode
	if !listener.CheckStatusCode(cfg.StatusCode) {
		s.Warnf("Invalid status code \"%d\", will use \"%d\"", cfg.StatusCode, http.StatusOK)
		s.statusCode = http.StatusOK
	}

	// Ensure a minimum keepalive
	if cfg.Keepalive < conf.MinKeepAlive {
		s.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		cfg.Keepalive = conf.MinKeepAlive
	}
	s.keepalive = cfg.Keepalive

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
			s.FatalWith("Failed to load Server Key", slog.F("ca_store", kp))
		} else if os.IsNotExist(sErr) && cfg.CaStore {
			s.DebugWith("Storing New Server Certificate", slog.F("ca_store", kp))
		} else {
			s.InfoWith("Importing existing Server Certificate", slog.F("ca_store", kp))
		}

		serverKeyPair, kErr = scrypt.ServerKeyPairFromFile(kp)
		if kErr != nil {
			s.FatalWith("Failed to load Server Key", slog.F("err", kErr))
		}
		privateKeySigner, prErr = scrypt.SignerFromKey(serverKeyPair.PrivateKey)
		if prErr != nil {
			s.FatalWith("Failed generate SSH signer", slog.F("err", prErr))
		}
	} else {
		serverKeyPair, kErr = scrypt.NewServerKeyPair()
		if kErr != nil {
			s.FatalWith("Failed to generate Server Key", slog.F("err", kErr))
		}
		privateKeySigner, prErr = scrypt.SignerFromKey(serverKeyPair.PrivateKey)
		if prErr != nil {
			s.FatalWith("Failed to create signer", slog.F("err", prErr))
		}

	}
	s.serverKey = privateKeySigner
	s.CertificateAuthority = serverKeyPair.CertificateAuthority
	s.sshConf.AddHostKey(s.serverKey)

	// Generate server fingerprint
	var fErr error
	s.fingerprint, fErr = scrypt.GenerateFingerprint(s.serverKey.PublicKey())
	if fErr != nil {
		s.Fatalf("Failed to generate server fingerprint")
	}
	s.InfoWith("Initializing server", slog.F("fingerprint", s.fingerprint))

	if cfg.Auth {
		s.Warnf("Client Authentication enabled, a valid certificate will be required")

		if s.certJarFile == "" {
			s.certJarFile = conf.GetSliderHome() + clientCertsFile
		}
		if lcErr := s.loadCertJar(); lcErr != nil {
			s.Fatalf("%v", lcErr)
		}

		s.sshConf.NoClientAuth = false
		s.sshConf.PublicKeyCallback = s.clientVerification
	} else {
		if s.certJarFile != "" {
			s.WarnWith("Client Authentication is disabled, certificates will be ignored", slog.F("cert_jar", s.certJarFile))
		}
	}

	if cfg.HttpRedirect != "" {
		wr, wErr := listener.ResolveURL(cfg.HttpRedirect)
		if wErr != nil {
			s.FatalWith("Bad Redirect URL", slog.F("url", cfg.HttpRedirect), slog.F("err", wErr))
		}
		s.urlRedirect = wr
		s.DebugWith("Redirecting incomming HTTP requests to", slog.F("url", s.urlRedirect))
	}

	fmtAddress := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
	serverAddr, rErr := net.ResolveTCPAddr("tcp", fmtAddress)
	if rErr != nil {
		s.Fatalf("Not a valid IP address \"%s\"", fmtAddress)
	}

	tlsOn := false
	tlsConfig := &tls.Config{}
	listenerProto := "tcp"
	if cfg.ListenerCert != "" && cfg.ListenerKey != "" {
		tlsOn = true
		listenerProto = "tls"
		if cfg.ListenerCA != "" {
			s.WarnWith("Using CA for TLS client verification", slog.F("ca", cfg.ListenerCA))
			caPem, rfErr := os.ReadFile(cfg.ListenerCA)
			if rfErr != nil {
				s.FatalWith("Failed to read CA file", slog.F("ca", cfg.ListenerCA), slog.F("err", rfErr))
			}
			if len(caPem) == 0 {
				s.FatalWith("CA file is empty", slog.F("ca", cfg.ListenerCA), slog.F("err", rfErr))
			}
			tlsConfig = scrypt.GetTLSClientVerifiedConfig(caPem)
		}
	} else {
		if s.authOn && s.httpConsoleOn {
			s.Fatalf("HTTP Console with authentication requires TLS")
		}
	}

	s.Infof("Starting listener %s://%s", listenerProto, serverAddr.String())
	go func() {
		handler := s.buildRouter()

		if tlsOn {
			httpSrv := &http.Server{
				Addr:      serverAddr.String(),
				TLSConfig: tlsConfig,
				ErrorLog:  slog.NewDummyLog(),
			}
			httpSrv.Handler = handler
			if sErr := httpSrv.ListenAndServeTLS(cfg.ListenerCert, cfg.ListenerKey); sErr != nil {
				s.FatalWith("TLS Listener error", slog.F("err", sErr))
			}
			return
		}
		if sErr := http.ListenAndServe(serverAddr.String(), handler); sErr != nil {
			s.FatalWith("Listener error", slog.F("err", sErr))
		}

	}()

	// Handle startup callback if configured
	if cfg.CallbackURL != "" {
		if !cfg.Gateway {
			s.Fatalf("--callback requires --gateway mode")
		}
		go func() {
			// Small delay to ensure server is ready
			time.Sleep(100 * time.Millisecond)

			cu, err := listener.ResolveURL(cfg.CallbackURL)
			if err != nil {
				s.ErrorWith("Failed to resolve callback URL",
					slog.F("url", cfg.CallbackURL),
					slog.F("err", err))
				return
			}

			// Retry loop for callback connection
			for {
				s.InfoWith("Initiating callback connection", slog.F("target", cu.String()))
				notifier := make(chan error, 1)

				// Start connection (blocks until disconnection or failure)
				s.newConnector(cu, notifier, 0, "", s.customProto, "", "", conf.OperationCallback)

				// Connection attempt finished (either failed immediately or disconnected)
				cErr := <-notifier
				if cErr != nil {
					s.ErrorWith("Callback connection failed",
						slog.F("target", cu.String()),
						slog.F("err", cErr))
				} else {
					s.InfoWith("Callback connection disconnected", slog.F("target", cu.String()))
				}

				// Exit if retry not enabled
				if !cfg.CallbackRetry {
					break
				}

				// Wait before retry
				s.DebugWith("Waiting before callback retry", slog.F("interval", s.keepalive))
				time.Sleep(s.keepalive)
			}
		}()
	}

	// Capture Interrupt Signal to toggle log output and activate Console
	if cfg.Headless {
		// In headless mode, just wait for interrupt signal to exit
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		s.Infof("Received interrupt signal, shutting down...")
	} else {
		// Normal mode with console
		s.Printf("Press CTR^C to access the Slider Console")
		var cmdOutput string
		for consoleToggle := true; consoleToggle; {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
			for range sig {
				// Stop capturing so we can capture as well on the console
				signal.Stop(sig)
				close(sig)
				// Send logs to a buffer
				s.LogToBuffer()
				// Run a Slider Console (NewConsole locks until termination),
				// 'cmdOutput' will always be equal to "bg" or "exit"
				cmdOutput = s.NewConsole()
				// Restore logs from buffer and resume output to stdout
				s.BufferOut()
				s.LogToStdout()
			}
			if cmdOutput == "exit" {
				consoleToggle = false
			}
		}
	}

	s.Infof("Server down...")
}
