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
	Verbose          string
	Address          string
	Port             int
	Keepalive        time.Duration
	Colorless        bool
	Auth             bool
	CertJarFile      string
	CaStore          bool
	CaStorePath      string
	TemplatePath     string
	ServerHeader     string
	HttpRedirect     string
	StatusCode       int
	HttpVersion      bool
	HttpHealth       bool
	HttpDirIndex     bool
	HttpDirIndexPath string
	HttpApiOn        bool
	CustomProto      string
	ListenerCert     string
	ListenerKey      string
	ListenerCA       string
	JsonLog          bool
	CallerLog        bool
}

// RunServer starts a server with the given configuration
func RunServer(cfg *ServerConfig) {
	sshConf := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-slider-server",
	}

	log := slog.NewLogger("Server")
	if cfg.JsonLog {
		log.WithJSON(true)
	} else {
		// It is safe to assume that if PTY is On then colors are supported.
		if interpreter.IsPtyOn() && !cfg.Colorless {
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
			Sessions: make(map[int64]*Session),
		},
		sshConf: sshConf,
		console: Console{
			FirstRun: true,
			History: &CustomHistory{
				entries: make([]string, 0),
				maxSize: conf.DefaultHistorySize,
			},
		},
		certTrack: &scrypt.CertTrack{
			Certs: make(map[int64]*scrypt.KeyPair),
		},
		certJarFile:      cfg.CertJarFile,
		authOn:           cfg.Auth,
		caStoreOn:        cfg.CaStore,
		urlRedirect:      &url.URL{},
		serverHeader:     cfg.ServerHeader,
		httpVersion:      cfg.HttpVersion,
		httpHealth:       cfg.HttpHealth,
		httpDirIndex:     cfg.HttpDirIndex,
		httpDirIndexPath: cfg.HttpDirIndexPath,
		httpApiOn:        cfg.HttpApiOn,
		customProto:      cfg.CustomProto,
	}

	if cfg.TemplatePath != "" {
		tErr := conf.CheckTemplate(cfg.TemplatePath)
		if tErr != nil {
			s.Fatalf("Wrong template: %s", tErr)
		}
		s.templatePath = cfg.TemplatePath
	}

	s.statusCode = cfg.StatusCode
	if !conf.CheckStatusCode(cfg.StatusCode) {
		s.Warnf("Invalid status code \"%d\", will use \"%d\"", cfg.StatusCode, http.StatusOK)
		s.statusCode = http.StatusOK
	}

	// Ensure a minimum keepalive
	if cfg.Keepalive < conf.MinKeepAlive {
		s.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		cfg.Keepalive = conf.MinKeepAlive
	}
	s.keepalive = cfg.Keepalive

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		s.Fatalf("%v", iErr)
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

	serverFp, fErr := scrypt.GenerateFingerprint(s.serverKey.PublicKey())
	if fErr != nil {
		s.Fatalf("Failed to generate server fingerprint")
	}
	s.Infof("Server Fingerprint: %s", serverFp)

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
			s.Warnf("Client Authentication is disabled, Certs File %s will be ignored", s.certJarFile)
		}
	}

	if cfg.HttpRedirect != "" {
		wr, wErr := conf.ResolveURL(cfg.HttpRedirect)
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
	}

	s.Infof("Starting listener %s://%s", listenerProto, serverAddr.String())
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
				s.FatalWith("TLS Listener error", slog.F("err", sErr))
			}
			return
		}
		if sErr := http.ListenAndServe(serverAddr.String(), handler); sErr != nil {
			s.FatalWith("Listener error", slog.F("err", sErr))
		}
	}()

	s.Printf("Press CTR^C to access the Slider Console")

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

	s.Infof("Server down...")
}
