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
		s.WithCaller().DebugWith("Received unsupported protocol", nil,
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
	}); hErr != nil {
		s.WithCaller().ErrorWith("Error handling HTTP request", slog.F("err", hErr))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := conf.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.WithCaller().ErrorWith("Failed to upgrade client", slog.F("host", r.Host), slog.F("err", err))
		return
	}
	defer func() { _ = wsConn.Close() }()

	s.WithCaller().Debugf("Upgraded client \"%s\" HTTP connection to WebSocket.", r.RemoteAddr)

	session := s.newWebSocketSession(wsConn)
	defer s.dropWebSocketSession(session)

	s.NewSSHServer(session)
}

func (s *server) newClientConnector(clientUrl *url.URL, notifier chan error, certID int64, customDNS string, customProto string, tlsCertPath string, tlsKeyPath string) {
	wsURL, wErr := conf.FormatToWS(clientUrl)
	if wErr != nil {
		s.WithCaller().ErrorWith("Failed to convert client URL to WebSocket URL", slog.F("err", wErr))
		notifier <- wErr
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, dErr := conf.CustomResolver(customDNS, clientUrl.Hostname())
		if dErr != nil {
			s.WithCaller().ErrorWith("Failed to resolve host:", nil, slog.F("host", clientUrl.Hostname()), slog.F("err", dErr))
			notifier <- dErr
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), clientUrl.Hostname(), ip, 1)
		s.WithCaller().DebugWith("Connecting to client", nil, slog.F("url", wsURL), slog.F("resolved_ip", ip))
	}

	wsConfig := conf.DefaultWebSocketDialer
	if wsURL.Scheme == "wss" {
		wsConfig.TLSClientConfig.InsecureSkipVerify = true
		if tlsCertPath != "" && tlsKeyPath != "" {
			cert, lErr := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
			if lErr != nil {
				s.WithCaller().ErrorWith("Failed to load TLS certificate", nil, slog.F("err", lErr))
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
		s.WithCaller().ErrorWith("Failed to open WebSocket connection", nil, slog.F("url", wsURL), slog.F("err", err))
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
			s.WithCaller().ErrorWith("Can't find certificate", nil, slog.F("id", certID), slog.F("err", kErr))
			notifier <- kErr
			return
		}
		session.addCertInfo(certID, keyPair.FingerPrint)

		signerKey, sErr := scrypt.SignerFromKey(keyPair.PrivateKey)
		if sErr != nil {
			s.WithCaller().ErrorWith("Failed to create client ssh signer", nil, slog.F("certID", certID), slog.F("err", sErr))
			notifier <- sErr
			return
		}
		sshConf.AddHostKey(signerKey)
	}
	session.setSSHConf(&sshConf)

	s.NewSSHServer(session)

}
