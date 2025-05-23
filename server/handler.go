package server

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"slider/pkg/conf"
	"slider/pkg/scrypt"
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
		s.Logger.Debugf("Received unsupported protocol: %s, and operation: %s", secProto, secOperation)
	}

	if hErr := conf.HandleHttpRequest(w, r, &types.HttpHandler{
		TemplatePath: s.templatePath,
		ServerHeader: s.serverHeader,
		StatusCode:   s.statusCode,
		UrlRedirect:  s.urlRedirect,
		VersionOn:    s.httpVersion,
		HealthOn:     s.httpHealth,
	}); hErr != nil {
		s.Logger.Errorf("Error handling HTTP request: %v", hErr)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Internal Server Error"))
	}
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := conf.DefaultWebSocketUpgrader

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.Logger.Errorf("Failed to upgrade client \"%s\": %v", r.Host, err)
		return
	}
	defer func() { _ = wsConn.Close() }()

	s.Logger.Debugf("Upgraded client \"%s\" HTTP connection to WebSocket.", r.RemoteAddr)

	session := s.newWebSocketSession(wsConn)
	defer s.dropWebSocketSession(session)

	s.NewSSHServer(session)
}

func (s *server) newClientConnector(clientUrl *url.URL, notifier chan bool, certID int64, customDNS string, customProto string, tlsCertPath string, tlsKeyPath string) {
	wsURL, wErr := conf.FormatToWS(clientUrl)
	if wErr != nil {
		s.Logger.Errorf("Failed to convert %s to WebSocket URL: %v", clientUrl.String(), wErr)
		return
	}

	wsURLStr := wsURL.String()
	if customDNS != "" {
		ip, dErr := conf.CustomResolver(customDNS, clientUrl.Hostname())
		if dErr != nil {
			s.Logger.Errorf("Failed to resolve host %s: %v", clientUrl.Hostname(), dErr)
			return
		}
		wsURLStr = strings.Replace(wsURL.String(), clientUrl.Hostname(), ip, 1)
		s.Logger.Debugf("Connecting to %s, resolved to IP: %s", wsURL, ip)
	}

	wsConfig := conf.DefaultWebSocketDialer
	if wsURL.Scheme == "wss" {
		wsConfig.TLSClientConfig.InsecureSkipVerify = true
		if tlsCertPath != "" && tlsKeyPath != "" {
			cert, lErr := tls.LoadX509KeyPair(tlsCertPath, tlsKeyPath)
			if lErr != nil {
				s.Logger.Errorf("Failed to load TLS certificate: %v", lErr)
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
		s.Logger.Errorf(
			"Failed to open a WebSocket connection to \"%s\": %v", wsURL, err)
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
			s.Logger.Errorf("Can't find certificate with id %d", certID)
			return
		}
		session.addCertInfo(certID, keyPair.FingerPrint)

		signerKey, sErr := scrypt.SignerFromKey(keyPair.PrivateKey)
		if sErr != nil {
			s.Logger.Errorf("Failed to create client ssh signer with certID %d key", certID)
			return
		}
		sshConf.AddHostKey(signerKey)
	}
	session.setSSHConf(&sshConf)

	s.NewSSHServer(session)

}
