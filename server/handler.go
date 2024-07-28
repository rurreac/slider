package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slider/pkg/conf"
	"slider/pkg/wtemplate"
	"strings"
)

func (s *server) handleHTTPClient(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		s.handleWebSocket(w, r)
		return
	}

	var svrHeader string
	status := http.StatusNotFound
	tmpl := "Not Found"

	if s.webTemplate != "" {
		t, tErr := wtemplate.GetTemplate(s.webTemplate)
		if tErr == nil {
			svrHeader = s.webTemplate
			status = http.StatusOK
			tmpl = t
		}
	}

	w.Header().Add("server", svrHeader)

	var wErr error
	switch r.URL.Path {
	case "/health":
		_, wErr = w.Write([]byte("OK"))
	case "/":
		w.WriteHeader(status)
		_, wErr = w.Write([]byte(tmpl))
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

func (s *server) newClientConnector(clientAddr *net.TCPAddr, notifier chan bool) {
	wsConfig := conf.DefaultWebSocketDialer

	wsConn, _, err := wsConfig.DialContext(
		context.Background(),
		fmt.Sprintf("ws://%s", clientAddr.String()), http.Header{})
	if err != nil {
		s.Logger.Errorf(
			"Failed to open a WebSocket connection to \"%s\": %v",
			clientAddr.String(),
			err,
		)
		return
	}
	defer func() { _ = wsConn.Close() }()

	session := s.newWebSocketSession(wsConn)
	session.setListenerOn(true)
	session.addSessionNotifier(notifier)

	defer s.dropWebSocketSession(session)

	s.NewSSHServer(session)
}
