package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slider/pkg/conf"
	"strings"
)

func (s *server) handleHTTPClient(w http.ResponseWriter, r *http.Request) {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) == "websocket" {
		s.handleWebSocket(w, r)
		return
	}
	var err error
	switch r.URL.Path {
	case "/health":
		_, err = w.Write([]byte("OK"))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, err = w.Write([]byte("Not Found"))
	}
	if err != nil {
		s.Logger.Errorf("handleClient: %v", err)
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

func (s *server) newClientConnector(clientAddr *net.TCPAddr, auth bool, notifier chan bool) {
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
	session.setListenerAuthOn(auth)
	session.addSessionNotifier(notifier)

	defer s.dropWebSocketSession(session)

	s.NewSSHServer(session)
}
