package client

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/listener"
	"slider/pkg/scrypt"
	"slider/pkg/session"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// Config holds all configuration for a client instance
type Config struct {
	Verbose       string
	Keepalive     time.Duration
	Colorless     bool
	Fingerprint   string
	Key           string
	ListenerOn    bool
	Port          int
	Address       string
	Retry         bool
	TemplatePath  string
	ServerHeader  string
	HttpRedirect  string
	StatusCode    int
	HttpVersion   bool
	HttpHealth    bool
	CustomDNS     string
	CustomProto   string
	ListenerCert  string
	ListenerKey   string
	ListenerCA    string
	ClientTlsCert string
	ClientTlsKey  string
	JsonLog       bool
	CallerLog     bool
	ServerURL     string
}

// RunClient starts a client with the given configuration
func RunClient(cfg *Config) {
	defer close(shutdown)

	log := slog.NewLogger("Client")

	i, iErr := interpreter.NewInterpreter()
	if iErr != nil {
		log.Fatalf("%v", iErr)
	}

	if cfg.JsonLog {
		log.WithJSON(true)
	} else {
		if i.ColorOn && !cfg.Colorless {
			log.WithColors(true)
		}
	}
	if cfg.CallerLog {
		log.WithCallerInfo(true)
	}
	lvErr := log.SetLevel(cfg.Verbose)
	if lvErr != nil {
		log.Fatalf("Wrong log level (%s): %s", cfg.Verbose, lvErr)
		return
	}

	c := client{
		Logger:   log,
		shutdown: make(chan bool, 1),
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*session.BidirectionalSession),
		},
		firstRun:    true,
		customProto: cfg.CustomProto,
		interpreter: i,
		listenerConf: &listenerConf{
			urlRedirect: &url.URL{},
			httpVersion: cfg.HttpVersion,
			httpHealth:  cfg.HttpHealth,
		},
	}

	if cfg.Keepalive < conf.MinKeepAlive {
		c.Logger.Debugf("Overriding KeepAlive to minimum allowed \"%v\"", conf.MinKeepAlive)
		cfg.Keepalive = conf.MinKeepAlive
	}
	c.keepalive = cfg.Keepalive

	c.sshConfig = &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		ClientVersion:   "SSH-slider-client",
		Timeout:         conf.Timeout,
	}

	if cfg.Key != "" {
		if aErr := c.enableKeyAuth(cfg.Key); aErr != nil {
			c.Logger.Fatalf("%s", aErr)
		}
	}

	if cfg.Fingerprint != "" {
		if fErr := c.loadFingerPrint(cfg.Fingerprint); fErr != nil {
			c.Logger.Fatalf("%s", fErr)
		}
		c.sshConfig.HostKeyCallback = c.verifyServerKey
	}

	// Check the use of extra headers for added functionality
	// https://developer.mozilla.org/en-US/docs/Web/HTTP/Protocol_upgrade_mechanism
	c.httpHeaders = http.Header{
		"Sec-WebSocket-Protocol":  {cfg.CustomProto},
		"Sec-WebSocket-Operation": {listener.OperationClient},
	}

	if cfg.ListenerOn {
		c.isListener = cfg.ListenerOn
		c.serverHeader = cfg.ServerHeader

		if cfg.TemplatePath != "" {
			tErr := listener.CheckTemplate(cfg.TemplatePath)
			if tErr != nil {
				c.Logger.Fatalf("Wrong template: %s", tErr)
			}
			c.templatePath = cfg.TemplatePath
		}

		c.statusCode = cfg.StatusCode
		if !listener.CheckStatusCode(cfg.StatusCode) {
			c.Logger.Warnf("Invalid status code (%d), will use %d", cfg.StatusCode, http.StatusOK)
			c.statusCode = http.StatusOK
		}

		if cfg.HttpRedirect != "" {
			wr, wErr := listener.ResolveURL(cfg.HttpRedirect)
			if wErr != nil {
				c.Logger.Fatalf("Bad Redirect URL: %v", wErr)
			}
			c.urlRedirect = wr
			c.Logger.DebugWith("Redirecting incomming HTTP requests",
				slog.F("url", c.urlRedirect.String()))
		}

		fmtAddress := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
		clientAddr, rErr := net.ResolveTCPAddr("tcp", fmtAddress)
		if rErr != nil {
			c.Logger.Fatalf("Not a valid IP address (%s)", fmtAddress)
		}

		tlsOn := false
		tlsConfig := &tls.Config{}
		listenerProto := "tcp"
		if cfg.ListenerCert != "" && cfg.ListenerKey != "" {
			tlsOn = true
			listenerProto = "tls"
			if cfg.ListenerCA != "" {
				c.Logger.DebugWith("Using CA for TLS client verification",
					slog.F("ca", cfg.ListenerCA))
				caPem, rfErr := os.ReadFile(cfg.ListenerCA)
				if rfErr != nil {
					c.Logger.FatalWith("Failed to read CA file",
						slog.F("ca", cfg.ListenerCA),
						slog.F("err", rfErr))
				}
				if len(caPem) == 0 {
					c.Logger.Fatalf("CA file is empty")
				}
				tlsConfig = scrypt.GetTLSClientVerifiedConfig(caPem)
			}
		}

		go func() {
			handler := c.buildRouter()

			if tlsOn {
				httpSrv := &http.Server{
					Addr:      clientAddr.String(),
					TLSConfig: tlsConfig,
					ErrorLog:  slog.NewDummyLog(),
				}
				httpSrv.Handler = handler
				if sErr := httpSrv.ListenAndServeTLS(cfg.ListenerCert, cfg.ListenerKey); sErr != nil {
					c.Logger.FatalWith("TLS Listener error",
						slog.F("err", sErr))
				}
				return
			}
			if sErr := http.ListenAndServe(clientAddr.String(), handler); sErr != nil {
				c.Logger.FatalWith("Listener failure",
					slog.F("err", sErr))
			}

		}()
		c.Logger.Infof("Listening on %s://%s", listenerProto, clientAddr.String())
		<-shutdown
	} else {
		su, uErr := listener.ResolveURL(cfg.ServerURL)
		if uErr != nil {
			c.Logger.Fatalf("Argument \"%s\" is not a valid URL", cfg.ServerURL)
		}

		c.serverURL = su
		c.wsConfig = listener.DefaultWebSocketDialer
		if cfg.ClientTlsCert != "" && cfg.ClientTlsKey != "" {
			tlsCert, lErr := tls.LoadX509KeyPair(cfg.ClientTlsCert, cfg.ClientTlsKey)
			if lErr != nil {
				c.Logger.FatalWith("Failed to load TLS certificate",
					slog.F("err", lErr))
			}
			c.wsConfig.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
		} else if cfg.ClientTlsCert != "" || cfg.ClientTlsKey != "" {
			c.Logger.FatalWith("Client TLS certificate or key provided but not both",
				slog.F("cert", cfg.ClientTlsCert),
				slog.F("key", cfg.ClientTlsKey))
		}

		for loop := true; loop; {
			c.startConnection(cfg.CustomDNS)

			// When the Client is not Listener a Server disconnection
			// will shut down the Client
			select {
			case <-shutdown:
				loop = false
			default:
				if !cfg.Retry || c.firstRun {
					loop = false
					continue
				}
				time.Sleep(c.keepalive)
			}
		}
	}

	c.Logger.Printf("Client down...")
}
