package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"slider/pkg/conf"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
	"slider/pkg/types"
	"strings"
)

func (s *server) handleHTTPClient(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		proto := conf.HttpVersionResponse.ProtoVersion
		if proto != s.customProto {
			proto = s.customProto
		}
		secProto := r.Header.Get("Sec-WebSocket-Protocol")
		secOperation := r.Header.Get("Sec-WebSocket-Operation")
		if secProto == proto && secOperation == "client" {
			s.handleWebSocket(w, r)
			return
		}
		s.DebugWith("Received unsupported protocol",
			slog.F("protocol", secProto),
			slog.F("operation", secOperation))
	}

	if hErr := conf.HandleHttpRequest(w, r, &types.HttpHandler{
		TemplatePath: s.templatePath,
		ServerHeader: s.serverHeader,
		StatusCode:   s.statusCode,
		UrlRedirect:  s.urlRedirect,
		VersionOn:    s.httpVersion,
		HealthOn:     s.httpHealth,
		DirIndexOn:   s.httpDirIndex,
		DirIndexPath: s.httpDirIndexPath,
		ApiOn:        s.httpApiOn,
		CertTrack:    s.certTrack,
	}); hErr != nil {
		s.ErrorWith("Error handling HTTP request", slog.F("err", hErr))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := conf.DefaultWebSocketUpgrader

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

	session := s.newWebSocketSession(wsConn)
	defer s.dropWebSocketSession(session)

	s.NewSSHServer(session)
}

func (s *server) newClientConnector(clientUrl *url.URL, notifier chan error, certID int64, customDNS string, customProto string, tlsCertPath string, tlsKeyPath string) {
	wsURL, wErr := conf.FormatToWS(clientUrl)
	if wErr != nil {
		s.ErrorWith("Failed to convert client URL to WebSocket URL", slog.F("err", wErr))
		notifier <- wErr
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, dErr := conf.CustomResolver(customDNS, clientUrl.Hostname())
		if dErr != nil {
			s.ErrorWith("Failed to resolve host:", slog.F("host", clientUrl.Hostname()), slog.F("err", dErr))
			notifier <- dErr
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), clientUrl.Hostname(), ip, 1)
		s.DebugWith("Connecting to client", slog.F("url", wsURL), slog.F("resolved_ip", ip))
	}

	wsConfig := conf.DefaultWebSocketDialer
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
		"Sec-WebSocket-Operation": {"server"},
	})
	if err != nil {
		s.ErrorWith("Failed to open WebSocket connection", slog.F("url", wsURL), slog.F("err", err))
		notifier <- err
		return
	}
	defer func() { _ = wsConn.Close() }()

	session := s.newWebSocketSession(wsConn)
	defer s.dropWebSocketSession(session)

	session.setListenerOn(true)
	session.addSessionNotifier(notifier)

	// Create a new ssh server configuration
	sshConf := *s.sshConf
	if certID != 0 {
		keyPair, kErr := s.getCert(certID)
		if kErr != nil {
			s.ErrorWith("Can't find certificate", slog.F("id", certID), slog.F("err", kErr))
			notifier <- kErr
			return
		}
		session.addCertInfo(certID, keyPair.FingerPrint)

		signerKey, sErr := scrypt.SignerFromKey(keyPair.PrivateKey)
		if sErr != nil {
			s.ErrorWith("Failed to create client ssh signer", slog.F("certID", certID), slog.F("err", sErr))
			notifier <- sErr
			return
		}
		sshConf.AddHostKey(signerKey)
	}
	session.setSSHConf(&sshConf)

	s.NewSSHServer(session)

}
