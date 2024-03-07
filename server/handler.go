package server

import (
	"github.com/gorilla/websocket"
	"html/template"
	"net/http"
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
	case "/stats":
		if s.conf.debug {
			statsTmpl := template.Must(template.New("stats").Parse(`
			{{if not .Sessions}}
				<div>No Sessions</div> 
			{{else}}
				<div>Active sessions: {{.SessionActive}}</div>
				{{range $sessionId, $addr := .Sessions }}
					<li>Session {{$addr}} -> {{$sessionId}}</li>
				{{end}}
			{{end}}`))
			if err = statsTmpl.Execute(w, s.sessionTrack); err == nil {
				return
			}
		}
		fallthrough
	default:
		w.WriteHeader(http.StatusNotFound)
		_, err = w.Write([]byte("Not Found"))
	}
	if err != nil {
		s.Errorf("handleClient: %s", err)
	}
}

func (s *server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	var upgrader = websocket.Upgrader{HandshakeTimeout: s.conf.timeout}

	wsConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.Errorf("Failed to upgrade client \"%s\": %s", r.Host, err)
		return
	}
	defer func() { _ = wsConn.Close() }()

	s.Debugf("Upgraded client \"%s\" HTTP connection to WebSocket.", r.RemoteAddr)

	session := s.newWebSocketSession(wsConn)
	defer s.dropWebSocketSession(session)

	s.NewSSHServer(session)
}
