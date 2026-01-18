package server

import (
	"os"
	"time"

	"slider/pkg/conf"

	"github.com/spf13/cobra"
)

// NewCommand creates the server cobra command
func NewCommand() *cobra.Command {
	var (
		verbose          string
		address          string
		port             int
		keepalive        time.Duration
		colorless        bool
		auth             bool
		certJarFile      string
		caStore          bool
		caStorePath      string
		templatePath     string
		serverHeader     string
		httpRedirect     string
		statusCode       int
		httpVersion      bool
		httpHealth       bool
		httpDirIndex     bool
		httpDirIndexPath string
		customProto      string
		listenerCert     string
		listenerKey      string
		listenerCA       string
		jsonLog          bool
		callerLog        bool
		headless         bool
		httpConsole      bool
		gateway          bool
		callbackURL      string
	)

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Runs a Slider Server instance",
		Long: `Creates a new Slider Server instance and waits for
incoming Slider Client connections on the defined port.

Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Build configuration from flags
			cfg := &Config{
				Verbose:          verbose,
				Address:          address,
				Port:             port,
				Keepalive:        keepalive,
				Colorless:        colorless,
				Auth:             auth,
				CertJarFile:      certJarFile,
				CaStore:          caStore,
				CaStorePath:      caStorePath,
				TemplatePath:     templatePath,
				ServerHeader:     serverHeader,
				HttpRedirect:     httpRedirect,
				StatusCode:       statusCode,
				HttpVersion:      httpVersion,
				HttpHealth:       httpHealth,
				HttpDirIndex:     httpDirIndex,
				HttpDirIndexPath: httpDirIndexPath,
				CustomProto:      customProto,
				ListenerCert:     listenerCert,
				ListenerKey:      listenerKey,
				ListenerCA:       listenerCA,
				JsonLog:          jsonLog,
				CallerLog:        callerLog,
				Headless:         headless,
				HttpConsole:      httpConsole,
				Gateway:          gateway,
				CallbackURL:      callbackURL,
			}

			// Call the RunServer function
			RunServer(cfg)
			return nil
		},
	}

	// Define flags
	cmd.Flags().StringVar(&verbose, "verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	cmd.Flags().StringVar(&address, "address", "0.0.0.0", "Server will bind to this address")
	cmd.Flags().IntVar(&port, "port", 8080, "port where Server will listen")
	cmd.Flags().DurationVar(&keepalive, "keepalive", conf.Keepalive, "Sets keepalive interval vs Clients")
	cmd.Flags().BoolVar(&colorless, "colorless", false, "Disables logging colors")
	cmd.Flags().BoolVar(&auth, "auth", false, "Requires authentication throughout the server")
	cmd.Flags().StringVar(&certJarFile, "certs", "", "Path of a valid slider-certs json file")
	cmd.Flags().BoolVar(&caStore, "ca-store", false, "Store Server JSON with key and CA for later use")
	cmd.Flags().StringVar(&caStorePath, "ca-store-path", "", "Path for reading and/or storing a Server JSON")
	cmd.Flags().StringVar(&templatePath, "http-template", "", "Path of a default file to serve")
	cmd.Flags().StringVar(&serverHeader, "http-server-header", "", "Sets a server header value")
	cmd.Flags().StringVar(&httpRedirect, "http-redirect", "", "Redirects incoming HTTP to given URL")
	cmd.Flags().IntVar(&statusCode, "http-status-code", 200, "Status code [200|301|302|400|401|403|500|502|503]")
	cmd.Flags().BoolVar(&httpVersion, "http-version", false, "Enables /version HTTP path")
	cmd.Flags().BoolVar(&httpHealth, "http-health", false, "Enables /health HTTP path")
	cmd.Flags().StringVar(&customProto, "proto", conf.Proto, "Set your own proto string")
	cmd.Flags().StringVar(&listenerCert, "listener-cert", "", "Certificate for SSL listener")
	cmd.Flags().StringVar(&listenerKey, "listener-key", "", "Key for SSL listener")
	cmd.Flags().StringVar(&listenerCA, "listener-ca", "", "CA for verifying client certificates")
	cmd.Flags().BoolVar(&headless, "headless", false, "Disables the internal console (CTR^C) and enables the Websocket Console")
	cmd.Flags().BoolVar(&httpConsole, "http-console", false, "Enables /console HTTP endpoint")
	cmd.Flags().BoolVar(&gateway, "gateway", false, "Enables Gateway mode (allows server chaining)")
	cmd.Flags().StringVar(&callbackURL, "callback", "", "Connect to server on startup and offer control (requires --gateway)")
	cmd.Flags().BoolVar(&jsonLog, "json-log", false, "Enables JSON formatted logging")
	if conf.Version == "development" {
		cmd.Flags().BoolVar(&callerLog, "caller-log", false, "Display caller information in logs")
		cmd.Flags().BoolVar(&httpDirIndex, "http-dir-index", false, "Enables /dir HTTP path with file browsing")
		cmd.Flags().StringVar(&httpDirIndexPath, "http-dir-index-path", "/dir", "Sets custom directory index path")
	}

	// Mark flag dependencies
	cmd.MarkFlagsRequiredTogether("listener-cert", "listener-key")
	if listenerCA != "" {
		cmd.MarkFlagsRequiredTogether("listener-ca", "listener-cert", "listener-key")
	}

	return cmd
}

// RunStandalone executes the server command directly (for standalone server binary)
func RunStandalone() {
	cmd := NewCommand()
	cmd.Use = "slider-server"

	// Add version subcommand
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Shows Binary Build info",
		Run: func(cmd *cobra.Command, args []string) {
			conf.PrintVersion()
		},
	}
	cmd.AddCommand(versionCmd)

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
