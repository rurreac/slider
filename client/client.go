package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/listener"
	"slider/pkg/sconn"
	"slider/pkg/scrypt"
	"slider/pkg/session"
	"slider/pkg/slog"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

type sessionTrack struct {
	SessionCount  int64                                   // Number of Sessions created
	SessionActive int64                                   // Number of Active Sessions
	Sessions      map[int64]*session.BidirectionalSession // Map of Sessions
}

type client struct {
	Logger            *slog.Logger
	serverURL         *url.URL
	keepalive         time.Duration
	wsConfig          *websocket.Dialer
	httpHeaders       http.Header
	sshConfig         *ssh.ClientConfig
	shutdown          chan bool
	serverFingerprint []string
	sessionTrack      *sessionTrack
	sessionTrackMutex sync.Mutex
	isListener        bool
	firstRun          bool
	customProto       string
	interpreter       *interpreter.Interpreter
	*listenerConf
}

type listenerConf struct {
	urlRedirect  *url.URL
	templatePath string
	httpVersion  bool
	httpHealth   bool
	serverHeader string
	statusCode   int
}

var shutdown = make(chan bool, 1)

func (c *client) startConnection(customDNS string) {
	wsURL, wErr := listener.FormatToWS(c.serverURL)
	if wErr != nil {
		c.Logger.ErrorWith("Failed to convert to WebSocket URL",
			slog.F("url", c.serverURL.String()),
			slog.F("err", wErr))
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, rErr := conf.CustomResolver(customDNS, c.serverURL.Hostname())
		if rErr != nil {
			c.Logger.ErrorWith("Failed to resolve host",
				slog.F("host", c.serverURL.Hostname()),
				slog.F("err", rErr))
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), c.serverURL.Hostname(), ip, 1)
		c.Logger.DebugWith("Connecting to WebSocket URL",
			slog.F("url", wsURLStr),
			slog.F("ip", ip))
	}

	if wsURL.Scheme == "wss" {
		c.wsConfig.TLSClientConfig.InsecureSkipVerify = true
	}

	wsConn, _, cErr := c.wsConfig.DialContext(context.Background(), wsURLStr, c.httpHeaders)
	if cErr != nil {
		c.Logger.ErrorWith("Can't connect to Server address",
			slog.F("err", cErr))
		return
	}
	sess := c.newWebSocketSession(wsConn)

	// Block until SSH connection closes
	c.newSSHClient(sess)
}

func (c *client) newSSHClient(sess *session.BidirectionalSession) {
	wsConn := sess.GetWebSocketConn()
	netConn := sconn.WsConnToNetConn(wsConn)

	var reqChan <-chan *ssh.Request
	var newChan <-chan ssh.NewChannel
	var connErr error

	clientConn, newChan, reqChan, connErr := ssh.NewClientConn(netConn, wsConn.RemoteAddr().String(), c.sshConfig)
	if connErr != nil {
		c.Logger.ErrorWith("SSH connection error",
			slog.F("err", connErr))
		return
	}

	// Create SSH client without passing newChan/reqChan
	// We handle channels and requests ourselves via handleGlobalChannels/handleGlobalRequests
	// If we pass them to NewClient, it will consume them and reject all incoming channels
	sshClient := ssh.NewClient(clientConn, nil, nil)

	// Update the existing session with the SSH client
	sess.SetSSHClient(sshClient)

	// Update endpoint instances with the SSH client connection
	if sess.GetShellInstance() != nil {
		sess.GetShellInstance().SetSSHConn(sshClient)
	}
	if sess.GetSocksInstance() != nil {
		sess.GetSocksInstance().SetSSHConn(sshClient)
	}
	if sess.GetSSHInstance() != nil {
		sess.GetSSHInstance().SetSSHConn(sshClient)
	}

	defer func() { _ = sess.Close() }()

	c.Logger.InfoWith("Server connected",
		slog.F("remote_addr", wsConn.RemoteAddr().String()))
	c.Logger.DebugWith("SSH connection established",
		slog.F("session_id", sess.GetID()))

	// Send Client Information to Server
	clientInfo := &conf.ClientInfo{Interpreter: c.interpreter}
	go c.sendClientInfo(sess, clientInfo)

	// Set keepalive after connection is established
	go sess.KeepAlive(c.keepalive)

	if c.firstRun {
		c.firstRun = false
	}

	// Use centralized channel routing
	go sess.HandleIncomingChannels(newChan)
	// Use centralized request handling
	go sess.HandleIncomingRequests(reqChan)

	// Block until connection closes
	_ = sshClient.Wait()
}

func (c *client) newWebSocketSession(wsConn *websocket.Conn) *session.BidirectionalSession {
	c.sessionTrackMutex.Lock()
	defer c.sessionTrackMutex.Unlock()

	// Create a session without SSH client (will be set later in newSSHClient)
	serverAddr := wsConn.RemoteAddr().String()
	sess := session.NewClientToServerSession(c.Logger, wsConn, nil, c.interpreter, serverAddr)
	sessionID := sess.GetID()
	c.sessionTrack.Sessions[sessionID] = sess

	c.Logger.DebugWith("Session Stats (↑)",
		slog.F("global", session.GetTotalCount()),
		slog.F("active", session.GetActiveCount()),
		slog.F("session_id", sessionID),
		slog.F("remote_addr", wsConn.RemoteAddr().String()))
	return sess
}

func (c *client) dropWebSocketSession(sess *session.BidirectionalSession) {
	c.sessionTrackMutex.Lock()
	defer c.sessionTrackMutex.Unlock()

	sessionID := sess.GetID()
	_ = sess.Close()

	c.Logger.DebugWith("Session Stats (↓)",
		slog.F("global", session.GetTotalCount()),
		slog.F("active", session.GetActiveCount()),
		slog.F("session_id", sessionID),
		slog.F("remote_addr", sess.GetWebSocketConn().RemoteAddr().String()))

	delete(c.sessionTrack.Sessions, sessionID)
}

func (c *client) enableKeyAuth(key string) error {
	signer, pErr := scrypt.SignerFromKey(key)
	if pErr != nil {
		return fmt.Errorf("failed to parse private key: %v", pErr)
	}
	c.sshConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	return nil
}

func (c *client) loadFingerPrint(fp string) error {
	// Check is fingerprint flag is a file or a fingerprint string
	// A file should contain a list of valid fingerprints
	fileInfo, sErr := os.Stat(fp)
	if sErr != nil {
		c.serverFingerprint = append(c.serverFingerprint, fp)
		return nil
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("fingerprint flag points to a directory not a file")
	}
	file, fErr := os.Open(fp)
	if fErr != nil {
		return fmt.Errorf("failed to read fingerprint file: %v", fErr)
	}
	scan := bufio.NewScanner(file)
	for scan.Scan() {
		if f := scan.Text(); f != "" {
			c.serverFingerprint = append(c.serverFingerprint, f)
		}
	}

	return nil
}

func (c *client) verifyServerKey(_ string, remote net.Addr, key ssh.PublicKey) error {
	serverFingerprint, fErr := scrypt.GenerateFingerprint(key)
	if fErr != nil {
		return fErr
	}

	if slices.Contains(c.serverFingerprint, serverFingerprint) {
		c.Logger.Infof("Server successfully vefified with provided fingerprint")
		return nil
	}

	return fmt.Errorf("server %s - verification failed (fingerprint: %s)", remote.String(), serverFingerprint)
}

func (c *client) sendClientInfo(sess *session.BidirectionalSession, ci *conf.ClientInfo) {
	clientInfoBytes, _ := json.Marshal(ci)
	ok, ciAnswerBytes, sErr := sess.SendRequest("client-info", true, clientInfoBytes)
	if sErr != nil || !ok {
		c.Logger.ErrorWith("Client information was not sent to server",
			slog.F("session_id", sess.GetID()),
			slog.F("err", sErr))
		return
	}
	if len(ciAnswerBytes) != 0 {
		ciAnswer := &interpreter.Interpreter{}
		if mErr := json.Unmarshal(ciAnswerBytes, ciAnswer); mErr == nil {
			c.Logger.DebugWith("Server identification received",
				slog.F("session_id", sess.GetID()),
				slog.F("server_system", ciAnswer.System))
			// Do not override client's shell with server's shell
			// The client should use its own native shell
		}
	}
}
