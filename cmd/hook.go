package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"slider/pkg/listener"

	"github.com/gorilla/websocket"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var hookCmd = &cobra.Command{
	Use:   "hook [flags] <server_url>",
	Short: "Connect to a Slider Server console via WebSocket",
	Long: `Connects to a Slider Server's web console endpoint (/console/ws)
and provides access to a remote slider console through your local terminal.
`,
	Args:         cobra.ExactArgs(1),
	RunE:         runHook,
	SilenceUsage: true,
}

// Hook flags
var (
	hookFingerprint string
	hookClientCert  string
	hookClientKey   string
	hookCA          string
	hookServerName  string
)

func init() {
	rootCmd.AddCommand(hookCmd)

	// Define flags
	hookCmd.Flags().StringVar(&hookFingerprint, "fingerprint", "", "Certificate fingerprint for authentication")
	hookCmd.Flags().StringVar(&hookClientCert, "client-cert", "", "Client certificate for mTLS")
	hookCmd.Flags().StringVar(&hookClientKey, "client-key", "", "Client private key for mTLS")
	hookCmd.Flags().StringVar(&hookCA, "ca", "", "CA certificate for server verification")
	hookCmd.Flags().StringVar(&hookServerName, "server-name", "", "Server name for TLS verification")

	// Mark flag dependencies
	hookCmd.MarkFlagsRequiredTogether("client-cert", "client-key")
	if hookServerName != "" {
		hookCmd.MarkFlagsRequiredTogether("ca", "server-name")
	}
}

func runHook(cmd *cobra.Command, args []string) error {
	serverURL := args[0]

	// Parse and validate server URL
	parsedURL, err := listener.ResolveURL(serverURL)
	if err != nil {
		return fmt.Errorf("invalid server URL: %w", err)
	}

	// Get authentication token if fingerprint is provided
	var token string
	var tlsConfig *tls.Config
	if hookFingerprint != "" {
		token, tlsConfig, err = getAuthToken(parsedURL, hookFingerprint, hookClientCert, hookClientKey, hookCA, hookServerName)
		if err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Connect to WebSocket console
	if err := connectToConsole(parsedURL, token, tlsConfig); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}

	return nil
}

// getAuthToken exchanges a fingerprint for a JWT token
func getAuthToken(baseURL *url.URL, fingerprint, certPath, keyPath, caPath, serverName string) (string, *tls.Config, error) {
	// Build auth token endpoint URL
	authURL := *baseURL
	authURL.Path = "/auth/token"

	// Create request body
	reqBody := map[string]string{
		"fingerprint": fingerprint,
	}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Configure HTTP client with mTLS if needed
	client := &http.Client{}
	tlsConfig := &tls.Config{}
	if (certPath != "" && keyPath != "") || caPath != "" {
		tlsConfig, err = buildTLSConfig(certPath, keyPath, caPath, serverName)
		if err != nil {
			return "", nil, err
		}
		client.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	// Make request
	req, err := http.NewRequest("POST", authURL.String(), strings.NewReader(string(jsonData)))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", nil, fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var tokenResp struct {
		Token     string `json:"token"`
		ExpiresAt string `json:"expires_at"`
		TokenType string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return tokenResp.Token, tlsConfig, nil
}

// buildTLSConfig creates a TLS configuration for mTLS
func buildTLSConfig(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	tlsConfig := &tls.Config{}

	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	// Load CA certificate if provided
	if caPath != "" {
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	if certPath != "" && keyPath != "" {
		// Load client certificate
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}

		// If CA is not provided, skip verification
		if caPath == "" {
			tlsConfig.InsecureSkipVerify = true
		}
	}

	return tlsConfig, nil
}

// connectToConsole establishes a WebSocket connection and bridges it with the local terminal
func connectToConsole(baseURL *url.URL, token string, tlsConfig *tls.Config) error {
	// Convert HTTP URL to WebSocket URL
	wsURL, err := listener.FormatToWS(baseURL)
	if err != nil {
		return fmt.Errorf("failed to convert URL to WebSocket: %w", err)
	}
	wsURL.Path = listener.ConsoleWsPath

	// Add token as query parameter if available
	if token != "" {
		query := wsURL.Query()
		query.Set("token", token)
		wsURL.RawQuery = query.Encode()
	}

	// Configure WebSocket dialer
	dialer := websocket.DefaultDialer
	if wsURL.Scheme == "wss" {
		dialer.TLSClientConfig = tlsConfig
	}

	// Connect to WebSocket
	fmt.Printf("Connecting to %s...\n", wsURL.String())
	wsConn, _, err := dialer.Dial(wsURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to WebSocket: %w", err)
	}
	defer func() { _ = wsConn.Close() }()

	// Put terminal in raw mode
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to set terminal to raw mode: %w", err)
	}

	// Ensure terminal is ALWAYS restored, even on panic
	defer func() {
		_ = term.Restore(int(os.Stdin.Fd()), oldState)
		// Print newline after terminal is restored to ensure clean output
		fmt.Println()
	}()

	// Channel to signal goroutine shutdown
	done := make(chan struct{})

	// Channel to signal connection closed (from either side)
	connClosed := make(chan struct{})

	// Goroutine: WebSocket → Stdout (remote output)
	go func() {
		defer close(connClosed)
		for {
			select {
			case <-done:
				return
			default:
				msgType, msg, err := wsConn.ReadMessage()
				if err != nil {
					// Connection closed - this is normal on exit
					return
				}

				if msgType == websocket.BinaryMessage || msgType == websocket.TextMessage {
					_, _ = os.Stdout.Write(msg)
				}
			}
		}
	}()

	// Goroutine: Stdin → WebSocket (local input)
	go func() {
		buf := make([]byte, 1024)
		for {
			select {
			case <-done:
				return
			default:
				n, err := os.Stdin.Read(buf)
				if err != nil {
					// Stdin closed or error - exit gracefully
					return
				}

				if n > 0 {
					if err := wsConn.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
						// Connection closed - exit gracefully
						return
					}
				}
			}
		}
	}()

	// Goroutine: Handle terminal resize
	go monitorWindowResize(wsConn, done)

	// Send initial terminal size
	sendTermSize(wsConn)

	// Connection closed by server (e.g., exit command) - this is normal
	<-connClosed

	// Signal all goroutines to stop
	close(done)

	return nil
}

func sendTermSize(conn *websocket.Conn) {
	width, height, err := term.GetSize(int(os.Stdin.Fd()))
	if err == nil {
		// Use struct to ensure consistent JSON field ordering
		resizeMsg := struct {
			Type string `json:"type"`
			Cols int    `json:"cols"`
			Rows int    `json:"rows"`
		}{
			Type: "resize",
			Cols: width,
			Rows: height,
		}
		if data, err := json.Marshal(resizeMsg); err == nil {
			_ = conn.WriteMessage(websocket.TextMessage, data)
		}
	}
}
