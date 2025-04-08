package server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"slider/pkg/conf"
	"slider/pkg/scrypt"
	"strings"
)

func (s *server) handleHTTPClient(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		s.handleWebSocket(w, r)
		return
	}

	w.Header().Add("server", s.webTemplate.ServerHeader)

	if s.webRedirect != "" {
		http.Redirect(w, r, s.webRedirect, http.StatusFound)
		return
	}

	var wErr error
	switch r.URL.Path {
	case "/":
		w.WriteHeader(s.webTemplate.StatusCode)
		_, wErr = w.Write([]byte(s.webTemplate.HtmlTemplate))
	default:
		http.Redirect(w, r, "/", http.StatusMovedPermanently)
	}
	if wErr != nil {
		s.Logger.Errorf("handleClient: %v", wErr)
	}
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var upgrader = conf.DefaultWebSocketUpgrader

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

func (s *server) newClientConnector(clientUrl *url.URL, notifier chan bool, certID int64) {
	wsConfig := conf.DefaultWebSocketDialer

	wsURL := fmt.Sprintf("ws://%s", strings.TrimPrefix(clientUrl.String(), clientUrl.Scheme+"://"))
	if clientUrl.Scheme == "https" {
		wsURL = fmt.Sprintf("wss://%s", strings.TrimPrefix(clientUrl.String(), clientUrl.Scheme+"://"))
	}

	wsConn, _, err := wsConfig.DialContext(context.Background(), wsURL, http.Header{})
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

	// Create new ssh server configuration
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
