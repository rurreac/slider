package cmd

import (
	"os"
	"time"

	"slider/pkg/conf"
	"slider/server"

	"github.com/spf13/cobra"
)

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Runs a Slider Server instance",
	Long: `Creates a new Slider Server instance and waits for
incoming Slider Client connections on the defined port.

Interaction with Slider Clients can be performed through
its integrated Console by pressing CTR^C at any time.`,
	Args:         cobra.NoArgs,
	RunE:         runServer,
	SilenceUsage: true,
}

// Server flags
var (
	sVerbose          string
	sAddress          string
	sPort             int
	sKeepalive        time.Duration
	sColorless        bool
	sAuth             bool
	sCertJarFile      string
	sCaStore          bool
	sCaStorePath      string
	sTemplatePath     string
	sServerHeader     string
	sHttpRedirect     string
	sStatusCode       int
	sHttpVersion      bool
	sHttpHealth       bool
	sHttpDirIndex     bool
	sHttpDirIndexPath string
	sCustomProto      string
	sListenerCert     string
	sListenerKey      string
	sListenerCA       string
	sJsonLog          bool
	sCallerLog        bool
	sHeadless         bool
	sHttpConsole      bool
)

func init() {
	rootCmd.AddCommand(serverCmd)

	// Define flags
	serverCmd.Flags().StringVar(&sVerbose, "verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	serverCmd.Flags().StringVar(&sAddress, "address", "0.0.0.0", "Server will bind to this address")
	serverCmd.Flags().IntVar(&sPort, "port", 8080, "port where Server will listen")
	serverCmd.Flags().DurationVar(&sKeepalive, "keepalive", conf.Keepalive, "Sets keepalive interval vs Clients")
	serverCmd.Flags().BoolVar(&sColorless, "colorless", false, "Disables logging colors")
	serverCmd.Flags().BoolVar(&sAuth, "auth", false, "Requires authentication throughout the server")
	serverCmd.Flags().StringVar(&sCertJarFile, "certs", "", "Path of a valid slider-certs json file")
	serverCmd.Flags().BoolVar(&sCaStore, "ca-store", false, "Store Server JSON with key and CA for later use")
	serverCmd.Flags().StringVar(&sCaStorePath, "ca-store-path", "", "Path for reading and/or storing a Server JSON")
	serverCmd.Flags().StringVar(&sTemplatePath, "http-template", "", "Path of a default file to serve")
	serverCmd.Flags().StringVar(&sServerHeader, "http-server-header", "", "Sets a server header value")
	serverCmd.Flags().StringVar(&sHttpRedirect, "http-redirect", "", "Redirects incoming HTTP to given URL")
	serverCmd.Flags().IntVar(&sStatusCode, "http-status-code", 200, "Status code [200|301|302|400|401|403|500|502|503]")
	serverCmd.Flags().BoolVar(&sHttpVersion, "http-version", false, "Enables /version HTTP path")
	serverCmd.Flags().BoolVar(&sHttpHealth, "http-health", false, "Enables /health HTTP path")
	serverCmd.Flags().StringVar(&sCustomProto, "proto", conf.Proto, "Set your own proto string")
	serverCmd.Flags().StringVar(&sListenerCert, "listener-cert", "", "Certificate for SSL listener")
	serverCmd.Flags().StringVar(&sListenerKey, "listener-key", "", "Key for SSL listener")
	serverCmd.Flags().StringVar(&sListenerCA, "listener-ca", "", "CA for verifying client certificates")
	serverCmd.Flags().BoolVar(&sHeadless, "headless", false, "Disables the internal console (CTR^C) and enables the Websocket Console")
	serverCmd.Flags().BoolVar(&sHttpConsole, "http-console", false, "Enables /console HTTP endpoint")
	serverCmd.Flags().BoolVar(&sJsonLog, "json-log", false, "Enables JSON formatted logging")
	if conf.Version == "development" {
		serverCmd.Flags().BoolVar(&sCallerLog, "caller-log", false, "Display caller information in logs")
		serverCmd.Flags().BoolVar(&sHttpDirIndex, "http-dir-index", false, "Enables /dir HTTP path with file browsing")
		serverCmd.Flags().StringVar(&sHttpDirIndexPath, "http-dir-index-path", "/dir", "Sets custom directory index path")
	}

	// Mark flag dependencies
	serverCmd.MarkFlagsRequiredTogether("listener-cert", "listener-key")
	if sListenerCA != "" {
		serverCmd.MarkFlagsRequiredTogether("listener-ca", "listener-cert", "listener-key")
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	// Build configuration from flags
	cfg := &server.ServerConfig{
		Verbose:          sVerbose,
		Address:          sAddress,
		Port:             sPort,
		Keepalive:        sKeepalive,
		Colorless:        sColorless,
		Auth:             sAuth,
		CertJarFile:      sCertJarFile,
		CaStore:          sCaStore,
		CaStorePath:      sCaStorePath,
		TemplatePath:     sTemplatePath,
		ServerHeader:     sServerHeader,
		HttpRedirect:     sHttpRedirect,
		StatusCode:       sStatusCode,
		HttpVersion:      sHttpVersion,
		HttpHealth:       sHttpHealth,
		HttpDirIndex:     sHttpDirIndex,
		HttpDirIndexPath: sHttpDirIndexPath,
		CustomProto:      sCustomProto,
		ListenerCert:     sListenerCert,
		ListenerKey:      sListenerKey,
		ListenerCA:       sListenerCA,
		JsonLog:          sJsonLog,
		CallerLog:        sCallerLog,
		Headless:         sHeadless,
		HttpConsole:      sHttpConsole,
	}

	// Call the new RunServer function
	server.RunServer(cfg)
	return nil
}

// RunServerCommand executes the server command directly (for standalone server binary)
func RunServerCommand() {
	// Use the existing serverCmd but execute it as a root command
	// We need to create a copy to avoid modifying the original
	standaloneCmd := &cobra.Command{
		Use:          serverCmd.Use,
		Short:        serverCmd.Short,
		Long:         serverCmd.Long,
		Args:         serverCmd.Args,
		RunE:         serverCmd.RunE,
		SilenceUsage: serverCmd.SilenceUsage,
	}

	// Copy flags from the original command
	standaloneCmd.Flags().AddFlagSet(serverCmd.Flags())

	// Add version subcommand
	standaloneCmd.AddCommand(versionCmd)

	if err := standaloneCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
