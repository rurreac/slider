package client

import (
	"fmt"
	"os"
	"time"

	"slider/pkg/conf"

	"github.com/spf13/cobra"
)

// NewCommand creates the client cobra command
func NewCommand() *cobra.Command {
	var (
		verbose       string
		keepalive     time.Duration
		colorless     bool
		fingerprint   string
		key           string
		listenerOn    bool
		beaconOn      bool
		port          int
		address       string
		retry         bool
		templatePath  string
		serverHeader  string
		httpRedirect  string
		statusCode    int
		httpVersion   bool
		httpHealth    bool
		customDNS     string
		customProto   string
		listenerCert  string
		listenerKey   string
		listenerCA    string
		clientTlsCert string
		clientTlsKey  string
		jsonLog       bool
		callerLog     bool
	)

	cmd := &cobra.Command{
		Use:   "client [server_address]",
		Short: "Runs a Slider Client instance",
		Long: `Creates a new Slider Client instance and connects
to the defined Slider Server.`,
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Custom validation for conditional exclusion
			if !listenerOn {
				// When not in listener mode, these flags should not be used
				conditionalFlags := []string{"fingerprint", "http-template",
					"http-server-header", "http-redirect", "http-status-code", "http-version",
					"http-health", "listener-cert", "listener-key", "listener-ca"}

				for _, flagName := range conditionalFlags {
					if cmd.Flags().Changed(flagName) {
						return fmt.Errorf("flag --%s requires --listener to be enabled", flagName)
					}
				}
			}

			// Validate argument count
			if !listenerOn && len(args) != 1 {
				return fmt.Errorf("client requires exactly one valid server address as an argument (unless in --listener mode)")
			}
			if listenerOn && len(args) > 0 {
				return fmt.Errorf("server address cannot be provided in --listener mode")
			}

			// Build configuration from flags
			cfg := &Config{
				Verbose:       verbose,
				Keepalive:     keepalive,
				Colorless:     colorless,
				Fingerprint:   fingerprint,
				Key:           key,
				ListenerOn:    listenerOn,
				BeaconOn:      beaconOn,
				Port:          port,
				Address:       address,
				Retry:         retry,
				TemplatePath:  templatePath,
				ServerHeader:  serverHeader,
				HttpRedirect:  httpRedirect,
				StatusCode:    statusCode,
				HttpVersion:   httpVersion,
				HttpHealth:    httpHealth,
				CustomDNS:     customDNS,
				CustomProto:   customProto,
				ListenerCert:  listenerCert,
				ListenerKey:   listenerKey,
				ListenerCA:    listenerCA,
				ClientTlsCert: clientTlsCert,
				ClientTlsKey:  clientTlsKey,
				JsonLog:       jsonLog,
				CallerLog:     callerLog,
			}

			// Add server URL if provided
			if len(args) > 0 {
				cfg.ServerURL = args[0]
			}

			// Call the RunClient function
			RunClient(cfg)
			return nil
		},
	}

	// Define flags
	cmd.Flags().StringVar(&verbose, "verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	cmd.Flags().DurationVar(&keepalive, "keepalive", conf.Keepalive, "Sets keepalive interval in seconds")
	cmd.Flags().BoolVar(&colorless, "colorless", false, "Disables logging colors")
	cmd.Flags().StringVar(&fingerprint, "fingerprint", "", "Server fingerprint for host verification (listener)")
	cmd.Flags().StringVar(&key, "key", "", "Private key for authenticating to a Server")
	cmd.Flags().BoolVar(&listenerOn, "listener", false, "Client will listen for incoming Server connections")
	cmd.Flags().BoolVar(&beaconOn, "beacon", false, "Client will also act as a Pivot (accepts Agents, connects to Server)")
	cmd.Flags().IntVar(&port, "port", 8081, "Listener port")
	cmd.Flags().StringVar(&address, "address", "0.0.0.0", "Address the Listener will bind to")
	cmd.Flags().BoolVar(&retry, "retry", false, "Retries reconnection indefinitely")
	cmd.Flags().StringVar(&templatePath, "http-template", "", "Path of a default file to serve (listener)")
	cmd.Flags().StringVar(&serverHeader, "http-server-header", "", "Sets a server header value (listener)")
	cmd.Flags().StringVar(&httpRedirect, "http-redirect", "", "Redirects incoming HTTP to given URL (listener)")
	cmd.Flags().IntVar(&statusCode, "http-status-code", 200, "Template Status code [200|301|302|400|401|403|500|502|503] (listener)")
	cmd.Flags().BoolVar(&httpVersion, "http-version", false, "Enables /version HTTP path")
	cmd.Flags().BoolVar(&httpHealth, "http-health", false, "Enables /health HTTP path")
	cmd.Flags().StringVar(&customDNS, "dns", "", "Uses custom DNS server <host[:port]> for resolving server address")
	cmd.Flags().StringVar(&customProto, "proto", conf.Proto, "Set your own proto string")
	cmd.Flags().StringVar(&listenerCert, "listener-cert", "", "Certificate for SSL listener")
	cmd.Flags().StringVar(&listenerKey, "listener-key", "", "Key for SSL listener")
	cmd.Flags().StringVar(&listenerCA, "listener-ca", "", "CA for verifying server certificates (mTLS)")
	cmd.Flags().StringVar(&clientTlsCert, "tls-cert", "", "TLS client Certificate")
	cmd.Flags().StringVar(&clientTlsKey, "tls-key", "", "TLS client Key")
	cmd.Flags().BoolVar(&jsonLog, "json-log", false, "Enables JSON formatted logging")
	if conf.Version == "development" {
		cmd.Flags().BoolVar(&callerLog, "caller-log", false, "Display caller information in logs")
	}

	// Mark mutual exclusions
	cmd.MarkFlagsMutuallyExclusive("listener", "beacon")
	cmd.MarkFlagsMutuallyExclusive("listener", "key")
	cmd.MarkFlagsMutuallyExclusive("listener", "dns")
	cmd.MarkFlagsMutuallyExclusive("listener", "retry")
	cmd.MarkFlagsMutuallyExclusive("listener", "tls-cert")
	cmd.MarkFlagsMutuallyExclusive("listener", "tls-key")

	// Mark flag dependencies
	cmd.MarkFlagsRequiredTogether("listener-cert", "listener-key")
	cmd.MarkFlagsRequiredTogether("listener-ca", "listener-cert", "listener-key")

	return cmd
}

// RunStandalone executes the client command directly (for standalone client binary)
func RunStandalone() {
	cmd := NewCommand()
	cmd.Use = "slider-client"

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
