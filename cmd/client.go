package cmd

import (
	"fmt"
	"time"

	"slider/client"
	"slider/pkg/conf"

	"github.com/spf13/cobra"
)

var clientCmd = &cobra.Command{
	Use:   "client [server_address]",
	Short: "Runs a Slider Client instance",
	Long: `Creates a new Slider Client instance and connects
to the defined Slider Server.`,
	Args:         cobra.MaximumNArgs(1),
	RunE:         runClient,
	SilenceUsage: true,
}

// Client flags
var (
	verbose       string
	keepalive     time.Duration
	colorless     bool
	fingerprint   string
	key           string
	listener      bool
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

func init() {
	rootCmd.AddCommand(clientCmd)

	// Define flags
	clientCmd.Flags().StringVar(&verbose, "verbose", "info", "Adds verbosity [debug|info|warn|error|off]")
	clientCmd.Flags().DurationVar(&keepalive, "keepalive", conf.Keepalive, "Sets keepalive interval in seconds")
	clientCmd.Flags().BoolVar(&colorless, "colorless", false, "Disables logging colors")
	clientCmd.Flags().StringVar(&fingerprint, "fingerprint", "", "Server fingerprint for host verification (listener)")
	clientCmd.Flags().StringVar(&key, "key", "", "Private key for authenticating to a Server")
	clientCmd.Flags().BoolVar(&listener, "listener", false, "Client will listen for incoming Server connections")
	clientCmd.Flags().IntVar(&port, "port", 8081, "Listener port")
	clientCmd.Flags().StringVar(&address, "address", "0.0.0.0", "Address the Listener will bind to")
	clientCmd.Flags().BoolVar(&retry, "retry", false, "Retries reconnection indefinitely")
	clientCmd.Flags().StringVar(&templatePath, "http-template", "", "Path of a default file to serve (listener)")
	clientCmd.Flags().StringVar(&serverHeader, "http-server-header", "", "Sets a server header value (listener)")
	clientCmd.Flags().StringVar(&httpRedirect, "http-redirect", "", "Redirects incoming HTTP to given URL (listener)")
	clientCmd.Flags().IntVar(&statusCode, "http-status-code", 200, "Template Status code [200|301|302|400|401|403|500|502|503] (listener)")
	clientCmd.Flags().BoolVar(&httpVersion, "http-version", false, "Enables /version HTTP path")
	clientCmd.Flags().BoolVar(&httpHealth, "http-health", false, "Enables /health HTTP path")
	clientCmd.Flags().StringVar(&customDNS, "dns", "", "Uses custom DNS server <host[:port]> for resolving server address")
	clientCmd.Flags().StringVar(&customProto, "proto", conf.Proto, "Set your own proto string")
	clientCmd.Flags().StringVar(&listenerCert, "listener-cert", "", "Certificate for SSL listener")
	clientCmd.Flags().StringVar(&listenerKey, "listener-key", "", "Key for SSL listener")
	clientCmd.Flags().StringVar(&listenerCA, "listener-ca", "", "CA for verifying client certificates")
	clientCmd.Flags().StringVar(&clientTlsCert, "tls-cert", "", "TLS client Certificate")
	clientCmd.Flags().StringVar(&clientTlsKey, "tls-key", "", "TLS client Key")
	clientCmd.Flags().BoolVar(&callerLog, "caller-log", false, "Display caller information in logs")
	if conf.Version == "development" {
		clientCmd.Flags().BoolVar(&jsonLog, "json-log", false, "Enables JSON formatted logging")
	}

	// Mark mutual exclusions
	clientCmd.MarkFlagsMutuallyExclusive("listener", "key")
	clientCmd.MarkFlagsMutuallyExclusive("listener", "dns")
	clientCmd.MarkFlagsMutuallyExclusive("listener", "retry")
	clientCmd.MarkFlagsMutuallyExclusive("listener", "tls-cert")
	clientCmd.MarkFlagsMutuallyExclusive("listener", "tls-key")

	// Mark flag dependencies
	clientCmd.MarkFlagsRequiredTogether("listener-cert", "listener-key")
	clientCmd.MarkFlagsRequiredTogether("listener-ca", "listener-cert", "listener-key")
}

func runClient(cmd *cobra.Command, args []string) error {
	// Custom validation for conditional exclusion
	if !listener {
		// When not in listener mode, these flags should not be used
		conditionalFlags := []string{"address", "port", "fingerprint", "http-template",
			"http-server-header", "http-redirect", "http-status-code", "http-version",
			"http-health", "listener-cert", "listener-key", "listener-ca"}

		for _, flagName := range conditionalFlags {
			if cmd.Flags().Changed(flagName) {
				return fmt.Errorf("flag --%s requires --listener to be enabled", flagName)
			}
		}
	}

	// Validate argument count based on listener mode
	if !listener && len(args) != 1 {
		return fmt.Errorf("client requires exactly one valid server address as an argument when not in listener mode")
	}
	if listener && len(args) > 0 {
		return fmt.Errorf("server address should not be provided in listener mode")
	}

	// Build configuration from flags
	cfg := &client.ClientConfig{
		Verbose:       verbose,
		Keepalive:     keepalive,
		Colorless:     colorless,
		Fingerprint:   fingerprint,
		Key:           key,
		Listener:      listener,
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

	// Add server URL if not in listener mode
	if !listener {
		cfg.ServerURL = args[0]
	}

	// Call the new RunClient function
	client.RunClient(cfg)
	return nil
}
