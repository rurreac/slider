package client

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"slider/pkg/conf"
	"slider/pkg/interpreter"
	"slider/pkg/sconn"
	"slider/pkg/scrypt"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/armon/go-socks5"

	"github.com/gorilla/websocket"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
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
	wsURL, wErr := conf.FormatToWS(c.serverURL)
	if wErr != nil {
		c.Logger.WithCaller().ErrorWith("Failed to convert to WebSocket URL", nil,
			slog.F("url", c.serverURL.String()),
			slog.F("err", wErr))
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, rErr := conf.CustomResolver(customDNS, c.serverURL.Hostname())
		if rErr != nil {
			c.Logger.WithCaller().ErrorWith("Failed to resolve host", nil,
				slog.F("host", c.serverURL.Hostname()),
				slog.F("err", rErr))
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), c.serverURL.Hostname(), ip, 1)
		c.Logger.WithCaller().DebugWith("Connecting to WebSocket URL", nil,
			slog.F("url", wsURLStr),
			slog.F("ip", ip))
	}

	if wsURL.Scheme == "wss" {
		c.wsConfig.TLSClientConfig.InsecureSkipVerify = true
	}

	wsConn, _, cErr := c.wsConfig.DialContext(context.Background(), wsURLStr, c.httpHeaders)
	if cErr != nil {
		c.Logger.WithCaller().ErrorWith("Can't connect to Server address", nil,
			slog.F("err", cErr))
		return
	}
	session := c.newWebSocketSession(wsConn)
	session.disconnect = make(chan bool, 1)

	go c.newSSHClient(session)

	<-session.disconnect
	close(session.disconnect)
}

func (c *client) newSSHClient(session *Session) {
	netConn := sconn.WsConnToNetConn(session.wsConn)

	var reqChan <-chan *ssh.Request
	var newChan <-chan ssh.NewChannel
	var connErr error

	session.sshConn, newChan, reqChan, connErr = ssh.NewClientConn(netConn, session.wsConn.RemoteAddr().String(), c.sshConfig)
	if connErr != nil {
		c.Logger.WithCaller().ErrorWith("SSH connection error", nil,
			slog.F("err", connErr))
		session.disconnect <- true
		return
	}
	defer func() { _ = session.sshConn.Close() }()
	c.Logger.WithCaller().InfoWith("Server connected", nil,
		slog.F("remote_addr", session.wsConn.RemoteAddr().String()))
	c.Logger.WithCaller().DebugWith("New SSH Session", nil,
		slog.F("session_id", session.sessionID))

	// Send Client Information to Server
	clientInfo := &conf.ClientInfo{Interpreter: session.interpreter}
	go session.sendClientInfo(clientInfo)

	// Set keepalive after connection is established
	go session.keepAlive(c.keepalive)

	if c.firstRun {
		c.firstRun = false
	}

	go session.handleGlobalChannels(newChan)
	session.handleGlobalRequests(reqChan)
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
		c.Logger.WithCaller().Infof("Server successfully vefified with provided fingerprint")
		return nil
	}

	return fmt.Errorf("server %s - verification failed (fingerprint: %s)", remote.String(), serverFingerprint)
}

func (s *Session) sendClientInfo(ci *conf.ClientInfo) {
	clientInfoBytes, _ := json.Marshal(ci)
	ok, ciAnswerBytes, sErr := s.sshConn.SendRequest("client-info", true, clientInfoBytes)
	if sErr != nil || !ok {
		s.Logger.WithCaller().ErrorWith("Client information was not sent to server", nil,
			slog.F("err", sErr))
		return
	}
	if len(ciAnswerBytes) != 0 {
		ciAnswer := &interpreter.Interpreter{}
		if mErr := json.Unmarshal(ciAnswerBytes, ciAnswer); mErr == nil {
			s.Logger.WithCaller().DebugWith("Server requested shell", nil,
				slog.F("session_id", s.sessionID),
				slog.F("shell", ciAnswer.AltShell))
			s.interpreter.Shell = ciAnswer.AltShell
		}
	}
}

func (s *Session) handleGlobalChannels(newChan <-chan ssh.NewChannel) {
	for nc := range newChan {
		s.Logger.WithCaller().DebugWith("Opening \"%s\" channel", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel", nc.ChannelType()))
		switch nc.ChannelType() {
		case "socks5":
			go s.handleSocksChannel(nc)
		case "sftp":
			go s.handleSFTPChannel(nc)
		case "shell":
			go s.handleShellChannel(nc)
		case "exec":
			go s.handleExecChannel(nc)
		case "init-size":
			// Blocking here to ensure it is serviced before another channel is opened
			s.handleInitSizeChannel(nc)
		case "direct-tcpip":
			go s.handleTcpIpChannel(nc)
		default:
			s.Logger.WithCaller().DebugWith("Rejected channel", nil,
				slog.F("session_id", s.sessionID),
				slog.F("channel", nc.ChannelType()))
			if rErr := nc.Reject(ssh.UnknownChannelType, ""); rErr != nil {
				s.Logger.WithCaller().WarnWith("Received Unknown channel type", nil,
					slog.F("session_id", s.sessionID),
					slog.F("channel", nc.ChannelType()),
					slog.F("err", rErr))
			}
		}
	}
}

func (s *Session) handleTcpIpChannel(nc ssh.NewChannel) {
	tcpIpMsg := &types.TcpIpChannelMsg{}
	if uErr := ssh.Unmarshal(nc.ExtraData(), tcpIpMsg); uErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to unmarshal channel data", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel", nc.ChannelType()),
			slog.F("data", nc.ExtraData()),
			slog.F("err", uErr))
		_ = nc.Reject(ssh.UnknownChannelType, "Failed to decode direct-tcpip data")
		return
	}
	s.Logger.WithCaller().DebugWith("Direct TCPIP channel request", nil,
		slog.F("session_id", s.sessionID),
		slog.F("dst_host", tcpIpMsg.DstHost),
		slog.F("dst_port", tcpIpMsg.DstPort))
	host := net.JoinHostPort(tcpIpMsg.DstHost, strconv.Itoa(int(tcpIpMsg.DstPort)))
	conn, cErr := net.Dial("tcp", host)
	if cErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to connect to destination", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel", nc.ChannelType()),
			slog.F("host", host),
			slog.F("err", cErr))
		_ = nc.Reject(ssh.Prohibited, "Failed to connect to destination")
		return
	}
	dChan, dReq, dErr := nc.Accept()
	if dErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to accept channel", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel", nc.ChannelType()),
			slog.F("err", dErr))
		_ = conn.Close()
		return
	}
	go ssh.DiscardRequests(dReq)
	_, _ = sio.PipeWithCancel(dChan, conn)
}

func (s *Session) handleGlobalRequests(requests <-chan *ssh.Request) {
	for req := range requests {
		switch req.Type {
		case "keep-alive":
			if err := s.replyConnRequest(req, true, []byte("pong")); err != nil {
				s.Logger.WithCaller().ErrorWith("Error sending keep-alive reply to Server", nil,
					slog.F("session_id", s.sessionID),
					slog.F("channel", req.Type),
					slog.F("err", err))
			}
		case "shutdown":
			s.Logger.WithCaller().WarnWith("Server requested Client shutdown", nil,
				slog.F("session_id", s.sessionID))
			_ = s.replyConnRequest(req, true, nil)
			shutdown <- true
			s.disconnect <- true
		case "tcpip-forward":
			go s.handleTcpIpForward(req)
		case "cancel-tcpip-forward":
			ok := false
			tcpIpForward := &types.TcpIpFwdRequest{}
			if uErr := ssh.Unmarshal(req.Payload, tcpIpForward); uErr == nil {
				if _, found := s.revPortFwdMap[tcpIpForward.BindPort]; found {
					if s.revPortFwdMap[tcpIpForward.BindPort].BindAddress == tcpIpForward.BindAddress {
						s.revPortFwdMap[tcpIpForward.BindPort].StopChan <- true
						ok = true
					}
				}
			}
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
		default:
			s.Logger.WithCaller().DebugWith("Received unknown Connection Request Type", nil,
				slog.F("session_id", s.sessionID),
				slog.F("request_type", req.Type))
			_ = req.Reply(false, nil)
		}
	}
}

func (s *Session) keepAlive(keepalive time.Duration) {
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()

	for {
		select {
		case <-s.disconnect:
			s.Logger.WithCaller().InfoWith("Disconnected from Server", nil,
				slog.F("session_id", s.sessionID),
				slog.F("remote", s.wsConn.RemoteAddr().String()))
			return
		case <-ticker.C:
			_, p, sendErr := s.sendConnRequest("keep-alive", true, []byte("ping"))
			if sendErr != nil || !bytes.Equal(p, []byte("pong")) {
				s.Logger.WithCaller().ErrorWith("KeepAlive Check Lost connection to Server", nil,
					slog.F("session_id", s.sessionID))
				s.disconnect <- true
			}
		}
	}
}

func (s *Session) sendConnRequest(reqType string, wantReply bool, payload []byte) (bool, []byte, error) {
	s.Logger.WithCaller().DebugWith("Sending Connection Request Type", nil,
		slog.F("session_id", s.sessionID),
		slog.F("request_type", reqType),
		slog.F("payload", payload))
	return s.sshConn.SendRequest(reqType, wantReply, payload)
}

func (s *Session) replyConnRequest(req *ssh.Request, reply bool, payload []byte) error {
	s.Logger.WithCaller().DebugWith("Replying Connection Request Type", nil,
		slog.F("session_id", s.sessionID),
		slog.F("request_type", req.Type),
		slog.F("payload", payload))
	return req.Reply(reply, payload)
}

func (s *Session) handleSocksChannel(channel ssh.NewChannel) {
	socksChan, req, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to accept channel", nil,
			slog.F("session_id", s.sessionID),
			slog.F("channel", channel.ChannelType()),
			slog.F("err", aErr))
		return
	}
	defer func() {
		s.Logger.WithCaller().DebugWith("Closing Socks Channel", nil,
			slog.F("session", s.sessionID))
		_ = socksChan.Close()
	}()
	go ssh.DiscardRequests(req)

	// Create a net.Conn from the SSH channel
	socksConn := sconn.SSHChannelToNetConn(socksChan)
	defer func() { _ = socksConn.Close() }()

	// Set up configuration for the SOCKS5 server
	socksConf := &socks5.Config{
		// Disable logging
		Logger: slog.NewDummyLog(),
	}

	// Create a new SOCKS5 server
	server, err := socks5.New(socksConf)
	if err != nil {
		s.Logger.WithCaller().ErrorWith("Failed to create SOCKS5 server", nil,
			slog.F("session", s.sessionID),
			slog.F("err", err))
		return
	}

	// Serve the connection
	s.Logger.WithCaller().DebugWith("Starting SOCKS5 server on connection", nil,
		slog.F("session", s.sessionID))
	if sErr := server.ServeConn(socksConn); sErr != nil {
		// Logging Errors as Debug as most of them are:
		// - Failed to handle request: EOF
		// - read: connection reset by peer
		s.Logger.WithCaller().DebugWith("Error in SOCKS5 server", nil,
			slog.F("session", s.sessionID),
			slog.F("err", sErr))
	}

	s.Logger.WithCaller().DebugWith("SOCKS5 server connection closed", nil,
		slog.F("session", s.sessionID))
}

func (s *Session) handleSFTPChannel(channel ssh.NewChannel) {
	s.Logger.WithCaller().DebugWith("Accepting SFTP channel request", nil,
		slog.F("session", s.sessionID))
	sftpChan, requests, aErr := channel.Accept()
	if aErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to accept channel", nil,
			slog.F("session", s.sessionID),
			slog.F("channel", channel.ChannelType()),
			slog.F("err", aErr))
		return
	}

	// Make sure the channel gets closed when we're done
	defer func() {
		s.Logger.WithCaller().DebugWith("Closing SFTP channel", nil,
			slog.F("session", s.sessionID))
		_ = sftpChan.Close()
	}()

	// Handle channel requests in the background
	go ssh.DiscardRequests(requests)

	// Create SFTP server options
	var serverOptions []sftp.ServerOption
	if s.Logger.IsDebug() {
		serverOptions = append(serverOptions, sftp.WithDebug(os.Stderr))
	}

	// Create the SFTP server with the configured options
	s.Logger.WithCaller().DebugWith("Initializing SFTP server", nil,
		slog.F("session", s.sessionID))
	server, err := sftp.NewServer(
		sftpChan,
		serverOptions...,
	)
	if err != nil {
		s.Logger.WithCaller().ErrorWith("Failed to create SFTP server", nil,
			slog.F("session", s.sessionID),
			slog.F("err", err))
		return
	}

	s.Logger.WithCaller().DebugWith("SFTP server started successfully", nil,
		slog.F("session", s.sessionID))

	// Serve SFTP connections
	if err := server.Serve(); err != nil {
		if err == io.EOF {
			s.Logger.WithCaller().DebugWith("SFTP client disconnected", nil,
				slog.F("session", s.sessionID))
		} else {
			s.Logger.WithCaller().ErrorWith("SFTP server error", nil,
				slog.F("session", s.sessionID),
				slog.F("err", err))
		}
	}

	s.Logger.WithCaller().DebugWith("SFTP server stopped", nil,
		slog.F("session", s.sessionID))
}

func (s *Session) handleInitSizeChannel(nc ssh.NewChannel) {
	channel, requests, err := nc.Accept()
	if err != nil {
		s.Logger.WithCaller().ErrorWith("Failed to accept channel", nil,
			slog.F("session", s.sessionID),
			slog.F("err", err))
		return
	}
	defer func() {
		_ = channel.Close()
		s.Logger.WithCaller().DebugWith("Closing INIT-SIZE channel", nil,
			slog.F("session", s.sessionID))
	}()
	payload := nc.ExtraData()
	go ssh.DiscardRequests(requests)
	s.Logger.WithCaller().DebugWith("SSH Effective \"req-pty\" size as \"init-size\" payload", nil,
		slog.F("session", s.sessionID),
		slog.F("payload", payload))
	if len(payload) > 0 {
		var winSize types.TermDimensions
		if jErr := json.Unmarshal(payload, &winSize); jErr != nil {
			s.Logger.WithCaller().ErrorWith("Failed to unmarshal terminal size payload", nil,
				slog.F("session", s.sessionID),
				slog.F("err", jErr))
		}
		s.setInitTermSize(winSize)
	}
}

func (s *Session) handleTcpIpForward(req *ssh.Request) {
	tcpIpForward := &types.CustomTcpIpFwdRequest{}
	if uErr := json.Unmarshal(req.Payload, tcpIpForward); uErr != nil {
		s.Logger.WithCaller().ErrorWith("Failed to unmarshal TcpIpFwdRequest request", nil,
			slog.F("session", s.sessionID),
			slog.F("err", uErr))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	fwdAddress := fmt.Sprintf("%s:%d", tcpIpForward.BindAddress, tcpIpForward.BindPort)
	listener, err := net.Listen("tcp", fwdAddress)
	if err != nil {
		s.Logger.WithCaller().ErrorWith("Failed to start reverse port forward listener", nil,
			slog.F("session", s.sessionID),
			slog.F("address", fwdAddress),
			slog.F("err", err))
		if req.WantReply {
			_ = req.Reply(false, nil)
		}
		return
	}

	// We may have asked to bind to port 0, we want it resolved, saved and send back to the server
	finalBindPort := listener.Addr().(*net.TCPAddr).Port
	s.Logger.WithCaller().DebugWith("Reverse Port Forward request binding",
		nil,
		slog.F("session", s.sessionID),
		slog.F("bind_address", tcpIpForward.BindAddress),
		slog.F("bind_port", tcpIpForward.BindPort),
		slog.F("fw_address", fwdAddress),
		slog.F("fw_port", finalBindPort),
	)
	// Answer when we know if we can create a listener and the final bound port
	if req.WantReply {
		dataBytes := make([]byte, 0)
		if tcpIpForward.BindPort == 0 {
			// If the port was 0, we need to send the final bound port
			data := types.TcpIpReqSuccess{BoundPort: uint32(finalBindPort)}
			dataBytes = ssh.Marshal(data)
		}

		_ = req.Reply(true, dataBytes)
	}
	// Override the coming structure with the final bound port
	tcpIpForward.BindPort = uint32(finalBindPort)

	stopChan := make(chan bool, 1)
	s.addTcpIpForward(tcpIpForward, stopChan)

	defer func() {
		_ = listener.Close()
		s.dropTcpIpForward(tcpIpForward.BindPort)
	}()

	for {
		select {
		case <-stopChan:
			return
		default:
			// Proceed
		}

		// Set a timeout to force checking the stop signal regularly
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(conf.Timeout))
		conn, lErr := listener.Accept()
		if lErr != nil {
			// Discard timeout errors
			var netErr net.Error
			if errors.As(lErr, &netErr) && netErr.Timeout() {
				continue
			}

			s.Logger.WithCaller().DebugWith("Error accepting connection on reverse port", nil,
				slog.F("session_id", s.sessionID),
				slog.F("bind_port", tcpIpForward.BindPort),
				slog.F("err", lErr))
			return
		}

		go func() {
			srcAddr := conn.RemoteAddr().(*net.TCPAddr)
			payload := &types.CustomTcpIpChannelMsg{
				IsSshConn: tcpIpForward.IsSshConn,
				TcpIpChannelMsg: &types.TcpIpChannelMsg{
					DstHost: tcpIpForward.BindAddress,
					DstPort: tcpIpForward.BindPort,
					SrcHost: srcAddr.IP.String(),
					SrcPort: uint32(srcAddr.Port),
				},
			}
			customMsgBytes, mErr := json.Marshal(payload)
			if mErr != nil {
				s.Logger.WithCaller().DebugWith("Failed to marshal custom message", nil,
					slog.F("session_id", s.sessionID),
					slog.F("bind_port", tcpIpForward.BindPort),
					slog.F("err", mErr))
				return
			}
			// Start a "forwarded-tcpip" channel. Circling back to the server
			channel, reqs, oErr := s.sshConn.OpenChannel("forwarded-tcpip", customMsgBytes)
			if oErr != nil {
				s.Logger.WithCaller().DebugWith("Failed to open forwarded-tcpip channel", nil,
					slog.F("session_id", s.sessionID),
					slog.F("err", oErr))
				return
			}
			defer func() { _ = channel.Close() }()
			go ssh.DiscardRequests(reqs)

			_, _ = sio.PipeWithCancel(conn, channel)

			s.Logger.WithCaller().DebugWith("Completed request to remote", nil,
				slog.F("session_id", s.sessionID),
				slog.F("bind_address", tcpIpForward.BindAddress),
				slog.F("bind_port", tcpIpForward.BindPort),
				slog.F("src_addr", srcAddr.IP.String()),
				slog.F("src_port", srcAddr.Port),
			)
		}()
	}
}
