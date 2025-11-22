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
	"slider/pkg/scrypt"
	"slider/pkg/slog"

	"golang.org/x/crypto/ssh"
)

// ClientConfig holds all configuration for a client instance
type ClientConfig struct {
	Verbose       string
	Keepalive     time.Duration
	Colorless     bool
	Fingerprint   string
	Key           string
	Listener      bool
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
	ServerURL     string // Only used when not in listener mode
}

// RunClient starts a client with the given configuration
func RunClient(cfg *ClientConfig) {
	defer close(shutdown)

	log := slog.NewLogger("Client")
	lvErr := log.SetLevel(cfg.Verbose)
	if lvErr != nil {
		fmt.Printf("wrong log level \"%s\", %s", cfg.Verbose, lvErr)
		return
	}

	// It is safe to assume that if PTY is On then colors are supported.
	if interpreter.IsPtyOn() && !cfg.Colorless {
		log.WithColors()
	}

	c := client{
		Logger:   log,
		shutdown: make(chan bool, 1),
		sessionTrack: &sessionTrack{
			Sessions: make(map[int64]*Session),
		},
		firstRun:    true,
		customProto: cfg.CustomProto,
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
		"Sec-WebSocket-Operation": {"client"},
	}

	if cfg.Listener {
		c.isListener = cfg.Listener
		c.serverHeader = cfg.ServerHeader

		if cfg.TemplatePath != "" {
			tErr := conf.CheckTemplate(cfg.TemplatePath)
			if tErr != nil {
				c.Logger.Fatalf("Wrong template: %s", tErr)
			}
			c.templatePath = cfg.TemplatePath
		}

		c.statusCode = cfg.StatusCode
		if !conf.CheckStatusCode(cfg.StatusCode) {
			c.Logger.Warnf("Invalid status code \"%d\", will use \"%d\"", cfg.StatusCode, http.StatusOK)
			c.statusCode = http.StatusOK
		}

		if cfg.HttpRedirect != "" {
			wr, wErr := conf.ResolveURL(cfg.HttpRedirect)
			if wErr != nil {
				c.Logger.Fatalf("Bad Redirect URL: %v", wErr)
			}
			c.urlRedirect = wr
			c.Logger.Debugf("Redirecting incomming HTTP requests to \"%s\"", c.urlRedirect.String())
		}

		fmtAddress := fmt.Sprintf("%s:%d", cfg.Address, cfg.Port)
		clientAddr, rErr := net.ResolveTCPAddr("tcp", fmtAddress)
		if rErr != nil {
			c.Logger.Fatalf("Not a valid IP address \"%s\"", fmtAddress)
		}

		tlsOn := false
		tlsConfig := &tls.Config{}
		listenerProto := "tcp"
		if cfg.ListenerCert != "" && cfg.ListenerKey != "" {
			tlsOn = true
			listenerProto = "tls"
			if cfg.ListenerCA != "" {
				c.Logger.Warnf("Using CA \"%s\" for TLS client verification", cfg.ListenerCA)
				caPem, rfErr := os.ReadFile(cfg.ListenerCA)
				if rfErr != nil {
					c.Logger.Fatalf("Failed to read CA file: %v", rfErr)
				}
				if len(caPem) == 0 {
					c.Logger.Fatalf("CA file is empty")
				}
				tlsConfig = scrypt.GetTLSClientVerifiedConfig(caPem)
			}
		}

		go func() {
			handler := http.Handler(http.HandlerFunc(c.handleHTTPConn))

			if tlsOn {
				httpSrv := &http.Server{
					Addr:      clientAddr.String(),
					TLSConfig: tlsConfig,
					ErrorLog:  slog.NewDummyLog(),
				}
				httpSrv.Handler = handler
				if sErr := httpSrv.ListenAndServeTLS(cfg.ListenerCert, cfg.ListenerKey); sErr != nil {
					c.Logger.Fatalf("TLS Listener error: %s", sErr)
				}
				return
			}
			if sErr := http.ListenAndServe(clientAddr.String(), handler); sErr != nil {
				c.Logger.Fatalf("Listener error: %s", sErr)
			}

		}()
		c.Logger.Infof("Listening on %s://%s", listenerProto, clientAddr.String())
		<-shutdown
	} else {
		su, uErr := conf.ResolveURL(cfg.ServerURL)
		if uErr != nil {
			c.Logger.Fatalf("Argument \"%s\" is not a valid URL", cfg.ServerURL)
		}

		c.serverURL = su
		c.wsConfig = conf.DefaultWebSocketDialer
		if cfg.ClientTlsCert != "" || cfg.ClientTlsKey != "" {
			tlsCert, lErr := tls.LoadX509KeyPair(cfg.ClientTlsCert, cfg.ClientTlsKey)
			if lErr != nil {
				c.Logger.Fatalf("Failed to load TLS certificate: %v", lErr)
			}
			c.wsConfig.TLSClientConfig = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
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
