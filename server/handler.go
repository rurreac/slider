package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slider/pkg/conf"
	"slider/pkg/listener"
	"slider/pkg/scrypt"
	"slider/pkg/session"
	"slider/pkg/slog"
	"slider/pkg/types"
	"strings"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// buildRouter creates the HTTP router with all configured endpoints
func (s *server) buildRouter() http.Handler {
	// Get base router with common endpoints
	mux := listener.NewRouter(&listener.RouterConfig{
		TemplatePath: s.templatePath,
		ServerHeader: s.serverHeader,
		StatusCode:   s.statusCode,
		UrlRedirect:  s.urlRedirect,
		HealthOn:     s.httpHealth,
		VersionOn:    s.httpVersion,
		ConsoleOn:    s.httpConsoleOn,
		AuthOn:       s.authOn,
	})

	// Add server-specific routes

	if s.httpConsoleOn {
		// Authentication endpoints & Console page
		if s.authOn {
			mux.HandleFunc(listener.AuthPath, s.handleAuthPage)       // GET: Login page
			mux.HandleFunc(listener.AuthLoginPath, s.handleAuthToken) // POST: JWT from fingerprint
			mux.HandleFunc(listener.AuthLogoutPath, s.handleLogout)   // POST: Logout
			// Console page endpoint protected by auth middleware
			mux.Handle(listener.ConsolePath, s.authMiddleware(http.HandlerFunc(s.handleConsolePage)))
		} else {
			mux.Handle(listener.ConsolePath, http.HandlerFunc(s.handleConsolePage))
		}

		// WebSocket console endpoint (auth handled differently due to WebSocket constraints)
		mux.HandleFunc(listener.ConsoleWsPath, func(w http.ResponseWriter, r *http.Request) {
			upgradeHeader := r.Header.Get("Upgrade")
			if strings.ToLower(upgradeHeader) == "websocket" {
				_ = s.handleWebSocketConsole(w, r)
				return
			}
			// If path matches but not a WebSocket request, return 400 instead of 404
			s.DebugWith("Received non-WebSocket request to console endpoint",
				slog.F("remote_addr", r.RemoteAddr),
				slog.F("headers", r.Header))
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("This endpoint requires a WebSocket connection."))
		})
	}

	// Set accepted operations
	acceptedOps := []string{conf.OperationAgent, conf.OperationCallback}
	if s.gateway {
		// Gateway servers can be controlled via OperationOperator
		acceptedOps = append(acceptedOps, conf.OperationOperator)
	}

	// Wrap with WebSocket upgrade check for client connections
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if listener.IsSliderWebSocket(r, s.customProto, acceptedOps) {
			s.handleWebSocket(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := listener.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.ErrorWith("Failed to upgrade client", slog.F("host", r.Host), slog.F("err", err))
		return
	}
	defer func() { _ = wsConn.Close() }()

	s.DebugWith(
		"Upgraded client HTTP connection to WebSocket.",
		slog.F("remote_addr", r.RemoteAddr),
	)

	// Create server session for incoming client connection
	remoteAddr := wsConn.RemoteAddr().String()
	opts := &session.ServerSessionOptions{
		CertificateAuthority: s.CertificateAuthority,
		ServerKey:            s.serverKey,
		AuthOn:               s.authOn,
	}

	biSession := session.NewServerFromClientSession(
		s.Logger,
		wsConn,
		nil,                 // sshServerConn will be set by NewSSHServer
		s.sshConf,           // SSH server config
		s.serverInterpreter, // Use server's local interpreter
		remoteAddr,          // hostIP
		opts,
	)

	// Determine role based on operation
	switch operationType := r.Header.Get("Sec-WebSocket-Operation"); operationType {

	// Callback agent connecting to us
	case conf.OperationAgent:
		if s.gateway {
			biSession.SetRole(session.GatewayListener)
		} else {
			biSession.SetRole(session.OperatorListener)
		}
		biSession.SetPeerRole(session.AgentConnector)
		// Regular agents are not gateways
		biSession.SetIsGateway(false)

	// Gateway server connecting to us wanting us to control it
	case conf.OperationCallback:
		biSession.SetRole(session.OperatorListener)
		biSession.SetPeerRole(session.AgentConnector)
		// Callback sources are gateways with potential children
		biSession.SetIsGateway(true)

	// OperationGateway: Server connecting to listening client
	// OperationOperator: Incoming management request (Someone wants to control US)
	case conf.OperationGateway, conf.OperationOperator:
		biSession.SetRole(session.AgentListener)
		biSession.SetPeerRole(session.OperatorConnector)

	// Default fallback
	default:
		biSession.SetRole(session.OperatorListener)
		biSession.SetPeerRole(session.AgentConnector)
		biSession.SetIsGateway(false)
	}

	// Add to server's session track
	s.sessionTrackMutex.Lock()
	s.sessionTrack.Sessions[biSession.GetID()] = biSession
	s.sessionTrack.SessionCount = biSession.GetID()
	s.sessionTrack.SessionActive++
	s.sessionTrackMutex.Unlock()

	defer func() {
		s.dropWebSocketSession(biSession)
		s.NotifyUpstreamDisconnect(biSession.GetID())
	}()

	if r.Header.Get("Sec-WebSocket-Operation") == conf.OperationCallback {
		// For callback connections, we (the receiver) act as the SSH Client (Controller)
		// while the gateway (initiator) acts as the SSH Server (Controlled)
		s.NewSSHClient(biSession)
	} else {
		// Standard behavior: we act as the SSH Server for agents/clients
		s.NewSSHServer(biSession)
	}
}

func (s *server) newConnector(targetUrl *url.URL, notifier chan error, certID int64, customDNS string, customProto string, tlsCertPath string, tlsKeyPath string, operation string) {
	// Check for self-connection attempts (any server type)
	// This applies to any connection mode, but particularly important for gateway connections
	targetHost := targetUrl.Hostname()
	targetPort := targetUrl.Port()

	// Resolve custom DNS first if specified (for accurate self-connection detection)
	resolvedHost := targetHost
	if customDNS != "" {
		ip, dErr := conf.CustomResolver(customDNS, targetHost)
		if dErr != nil {
			s.ErrorWith("Failed to resolve host:", slog.F("host", targetHost), slog.F("err", dErr))
			notifier <- dErr
			return
		}
		resolvedHost = ip
	}

	// Check if we're trying to connect to ourselves
	if s.isSelfConnection(resolvedHost, targetPort) {
		err := fmt.Errorf("cannot connect to self (target=%s:%s, server=%s:%d)", targetHost, targetPort, s.host, s.port)
		s.WarnWith("Self-connection attempt blocked",
			slog.F("target", targetUrl.String()),
			slog.F("server_host", s.host),
			slog.F("server_port", s.port))
		notifier <- err
		return
	}

	wsURL, wErr := listener.FormatToWS(targetUrl)
	if wErr != nil {
		s.ErrorWith("Failed to convert client URL to WebSocket URL", slog.F("err", wErr))
		notifier <- wErr
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, dErr := conf.CustomResolver(customDNS, targetUrl.Hostname())
		if dErr != nil {
			s.ErrorWith("Failed to resolve host:", slog.F("host", targetUrl.Hostname()), slog.F("err", dErr))
			notifier <- dErr
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), targetUrl.Hostname(), ip, 1)
		s.DebugWith("Connecting to client", slog.F("url", wsURL), slog.F("resolved_ip", ip))
	}

	wsConfig := listener.DefaultWebSocketDialer
	if wsURL.Scheme == "wss" {
		wsConfig.TLSClientConfig.InsecureSkipVerify = true
		if tlsCertPath != "" && tlsKeyPath != "" {
			cert, lErr := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
			if lErr != nil {
				s.ErrorWith("Failed to load TLS certificate", slog.F("err", lErr))
				notifier <- lErr
				return
			}
			wsConfig.TLSClientConfig.Certificates = []tls.Certificate{cert}
		}

	}

	wsConn, _, err := wsConfig.DialContext(context.Background(), wsURLStr, http.Header{
		"Sec-WebSocket-Protocol":  {customProto},
		"Sec-WebSocket-Operation": {operation},
	})
	if err != nil {
		s.ErrorWith("Failed to open WebSocket connection", slog.F("url", wsURL), slog.F("err", err))
		notifier <- err
		return
	}
	defer func() { _ = wsConn.Close() }()

	// Create a new ssh configuration for this connection
	sshConf := *s.sshConf
	if certID != 0 {
		keyPair, kErr := s.getCert(certID)
		if kErr != nil {
			s.ErrorWith("Can't find certificate", slog.F("id", certID), slog.F("err", kErr))
			notifier <- kErr
			return
		}

		signerKey, sErr := scrypt.SignerFromKey(keyPair.PrivateKey)
		if sErr != nil {
			s.ErrorWith("Failed to create client ssh signer", slog.F("certID", certID), slog.F("err", sErr))
			notifier <- sErr
			return
		}
		sshConf.AddHostKey(signerKey)
	}

	// Create session with the appropriate role based on connection mode
	remoteAddr := wsConn.RemoteAddr().String()
	opts := &session.ServerSessionOptions{
		CertificateAuthority: s.CertificateAuthority,
		ServerKey:            s.serverKey,
		AuthOn:               s.authOn,
	}

	var biSession *session.BidirectionalSession

	switch operation {
	case conf.OperationOperator:
		// Gateway mode: we're a server connecting TO another server as a client (we control them)
		biSession = session.NewServerToServerSession(
			s.Logger,
			wsConn,
			nil,                 // sshClient will be set by NewSSHClient
			s.serverInterpreter, // Use server's local interpreter
			remoteAddr,
			opts,
		)
		biSession.SetRole(session.OperatorConnector)
		biSession.SetPeerRole(session.GatewayListener)
		biSession.SetIsGateway(true)

	case conf.OperationCallback:
		// Callback mode: we connect but THEY control US (expose our shell)
		biSession = session.NewServerToListenerSession(
			s.Logger,
			wsConn,
			nil,                 // sshServerConn will be set by NewSSHServer
			&sshConf,            // SSH server config
			s.serverInterpreter, // Use server's local interpreter
			remoteAddr,
			opts,
		)
		biSession.SetRole(session.AgentConnector)
		biSession.SetPeerRole(session.OperatorListener)
		biSession.SetIsGateway(false)

	default: // conf.OperationGateway
		// Listener mode: we're a server connecting TO a client acting as a server (we control them)
		biSession = session.NewServerToListenerSession(
			s.Logger,
			wsConn,
			nil,                 // sshServerConn will be set by NewSSHServer
			&sshConf,            // SSH server config
			s.serverInterpreter, // Use server's local interpreter
			remoteAddr,
			opts,
		)
		biSession.SetRole(session.OperatorConnector)
		biSession.SetPeerRole(session.AgentListener)
		biSession.SetIsGateway(false)
	}

	// Set certificate info if we have one
	if certID != 0 {
		keyPair, _ := s.getCert(certID)
		biSession.SetCertInfo(certID, keyPair.FingerPrint)
	}

	// Add to server's session track
	s.sessionTrackMutex.Lock()
	s.sessionTrack.Sessions[biSession.GetID()] = biSession
	s.sessionTrack.SessionCount = biSession.GetID()
	s.sessionTrack.SessionActive++
	s.sessionTrackMutex.Unlock()

	defer s.dropWebSocketSession(biSession)

	biSession.AddNotifier(notifier)
	biSession.SetSSHConfig(&sshConf)

	switch operation {
	case conf.OperationOperator:
		// Gateway mode: we act as SSH client (control the remote server)
		s.NewSSHClient(biSession)
	case conf.OperationCallback:
		// Callback mode: we act as SSH server (expose our shell to be controlled)
		s.NewSSHServer(biSession)
	default:
		// Standard listener connection: we act as SSH server
		s.NewSSHServer(biSession)
	}

}

// handleWebSocketConsole upgrades HTTP to WebSocket and bridges to a PTY console
func (s *server) handleWebSocketConsole(w http.ResponseWriter, r *http.Request) error {
	if s.authOn {
		// Extract token from cookie or query parameter
		token := extractTokenFromRequest(r)
		if token == "" {
			token = r.URL.Query().Get("token")
		}

		if token == "" {
			s.DebugWith("WebSocket connection rejected: missing token",
				slog.F("remote_addr", r.RemoteAddr))
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Missing authentication token"))
			return fmt.Errorf("missing token")
		}

		// Try to validate as JWT first, fall back to fingerprint for backward compatibility
		fingerprint, certID, err := s.validateToken(token)
		if err != nil {
			s.DebugWith("WebSocket connection rejected: invalid token",
				slog.F("remote_addr", r.RemoteAddr),
				slog.F("err", err))
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Invalid or expired token"))
			return err
		}

		s.DebugWith("WebSocket console authenticated",
			slog.F("remote_addr", r.RemoteAddr),
			slog.F("fingerprint", fingerprint),
			slog.F("cert_id", certID))
	}

	upgrader := listener.DefaultWebSocketUpgrader
	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true // Allow all origins
	}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.ErrorWith("Failed to upgrade client",
			slog.F("remote_addr", r.RemoteAddr),
			slog.F("err", err))
		return err
	}
	defer func() { _ = wsConn.Close() }()

	s.DebugWith(
		"Upgraded client HTTP connection to WebSocket.",
		slog.F("remote_addr", r.RemoteAddr),
	)

	// Create a pseudo-terminal pair
	ptyMaster, ptyTTY, err := pty.Open()
	if err != nil {
		s.ErrorWith("Failed to open PTY",
			slog.F("remote_addr", r.RemoteAddr),
			slog.F("err", err))
		return err
	}
	defer func() { _ = ptyMaster.Close() }()
	defer func() { _ = ptyTTY.Close() }()

	// Set PTY size (default 80x24)
	if err := pty.Setsize(ptyMaster, &pty.Winsize{
		Rows: 24,
		Cols: 80,
	}); err != nil {
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte("Failed to set PTY size"))
		s.ErrorWith("Failed to set PTY size",
			slog.F("remote_addr", r.RemoteAddr),
			slog.F("err", err))
		return err
	}

	// Setup Console
	webTermHistory := session.DefaultHistory
	webConsole, err := s.newWebConsole(ptyTTY, webTermHistory)
	if err != nil {
		s.ErrorWith("Failed to create WebConsole",
			slog.F("remote_addr", r.RemoteAddr),
			slog.F("err", err))
		return err
	}
	// Channel to signal goroutine shutdown
	done := make(chan struct{})
	defer close(done)

	// Goroutine: WebSocket → PTY (user input)
	go func() {
		defer func() { _ = ptyMaster.Close() }()
		for {
			select {
			case <-done:
				return
			default:
				msgType, msg, err := wsConn.ReadMessage()
				if err != nil {
					return
				}

				if msgType == websocket.TextMessage {
					// Check for resize message
					if strings.HasPrefix(string(msg), "{\"type\":\"resize\"") {
						var resizeMsg struct {
							Type string `json:"type"`
							Cols uint16 `json:"cols"`
							Rows uint16 `json:"rows"`
						}
						if err := json.Unmarshal(msg, &resizeMsg); err == nil {
							_ = pty.Setsize(ptyMaster, &pty.Winsize{
								Rows: resizeMsg.Rows,
								Cols: resizeMsg.Cols,
							})
							_ = webConsole.Term.SetSize(int(resizeMsg.Cols), int(resizeMsg.Rows))

							_ = webConsole.Term.SetSize(int(resizeMsg.Cols), int(resizeMsg.Rows))

							// Propagate resize to the active command in this console
							if webConsole.ResizeChan != nil {
								select {
								case webConsole.ResizeChan <- types.TermDimensions{Width: uint32(resizeMsg.Cols), Height: uint32(resizeMsg.Rows)}:
								default:
									// Channel full, skip
								}
							}
						}
						continue
					}
				}

				// Write user input to PTY
				if _, err := ptyMaster.Write(msg); err != nil {
					return
				}
			}
		}
	}()

	// Goroutine: PTY → WebSocket (console output)
	go func() {
		buf := make([]byte, 4096)
		for {
			select {
			case <-done:
				return
			default:
				n, err := ptyMaster.Read(buf)
				if err != nil {
					return
				}

				if err := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					return
				}
			}
		}
	}()

	// Display banner once the bridge is ready
	s.consoleBanner(webConsole)

	// Main goroutine: Console command loop
	for {
		line, err := webConsole.Term.ReadLine()
		if err != nil {
			if err != io.EOF {
				webConsole.PrintError("Failed to read input: %s", err)
			}
			if webConsole, err = s.newWebConsole(ptyTTY, webTermHistory); err != nil {
				webConsole.PrintError("Failed to create new terminal: %s", err)
			}
			_, _ = webConsole.Term.Write([]byte("\r\n"))
			continue
		}

		// Parse command
		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		command := strings.ToLower(parts[0])
		args := parts[1:]

		// Create execution context
		ctx := &ExecutionContext{
			server:  s,
			session: nil, // No session for web console
			ui:      webConsole,
		}

		// Execute command
		if err := s.commandRegistry.Execute(ctx, command, args); err != nil {
			if errors.Is(err, ErrExitConsole) {
				webConsole.PrintlnGreyOut("Disconnecting...")
				return nil
			}
			s.ErrorWith("Failed to execute command", slog.F("command", command), slog.F("args", args), slog.F("err", err))
			webConsole.PrintError("Error: %v", err)
		}

		// Reset prompt
		webConsole.Term.SetPrompt(getPrompt())
	}
}

func (s *server) newWebConsole(ptyTTY *os.File, history *session.CustomHistory) (*Console, error) {
	if _, err := term.MakeRaw(int(ptyTTY.Fd())); err != nil {
		return nil, err
	}
	webConsole := &Console{
		Term:       term.NewTerminal(ptyTTY, getPrompt()),
		ReadWriter: ptyTTY,
		History:    history,
		ResizeChan: make(chan types.TermDimensions, 10),
	}

	// Initialize command registry if needed
	if s.commandRegistry == nil {
		s.initRegistry()
	}

	// Set auto complete
	webConsole.setConsoleAutoComplete(s.commandRegistry, s.serverInterpreter)

	return webConsole, nil
}
