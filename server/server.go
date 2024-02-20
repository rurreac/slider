package server

import (
	"flag"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slider/pkg/scrypt"
	"slider/pkg/slog"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

// config creates the server configuration build from flags
type config struct {
	keyGen    bool
	keyFile   string
	authFile  string
	addr      address
	timeout   time.Duration
	keepalive time.Duration
	debug     bool
}

type address struct {
	host string
	port string
}

// sessionTrack keeps track of sessions and clients
type sessionTrack struct {
	SessionCount  int64              // Number of Sessions created
	SessionActive int64              // Number of Active Sessions
	Sessions      map[int64]*Session // Map of Sessions
}

// Session represents a session from a client to the server
type Session struct {
	host          string
	sessionID     int64
	shellWsConn   *websocket.Conn
	shellConn     *ssh.ServerConn
	shellChannel  ssh.Channel
	shellOpened   bool
	rawTerm       bool
	KeepAliveChan chan bool
}

type server struct {
	*slog.Logger
	conf         *config
	sshConf      *ssh.ServerConfig
	sessionTrack *sessionTrack
	console      *term.Terminal
	consoleState *term.State
}

func NewServer(args []string) {
	conf := &config{}
	sshConf := &ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-slider-server",
	}
	f := flag.NewFlagSet("Server", flag.ContinueOnError)
	f.BoolVar(&conf.debug, "debug", false, "Add verbose messages")
	f.StringVar(&conf.addr.host, "address", "0.0.0.0", "Address to run the server")
	f.StringVar(&conf.addr.port, "port", "8080", "Port to run the server")
	f.DurationVar(&conf.timeout, "timeout", 60*time.Second, "Set global handshake timeout in seconds.")
	f.DurationVar(&conf.keepalive, "keepalive", 30*time.Second, "Set global handshake timeout in seconds.")
	// TODO: Below flags not implemented
	f.StringVar(&conf.keyFile, "key", "", "Path of key to use or generate in if absent")
	f.BoolVar(&conf.keyGen, "keygen", false, "Save generated certificate to disk")
	if parsErr := f.Parse(args); parsErr != nil {
		return
	}

	signer, err := scrypt.CreateSSHKeys(*sshConf, conf.keyGen)
	if err != nil {
		panic(err)
	}
	sshConf.AddHostKey(signer)

	s := &server{
		conf:   conf,
		Logger: slog.NewLogger("Server"),
		sessionTrack: &sessionTrack{
			SessionCount:  0,
			SessionActive: 0,
			Sessions:      make(map[int64]*Session),
		},
		sshConf: sshConf,
	}
	if s.conf.debug {
		s.WithDebug()
	}
	l, lisErr := s.listener(conf.addr.host, conf.addr.port)
	if lisErr != nil {
		s.Fatalf("listener: %s", err)
	}

	s.Infof("listening on %s://%s:%s", l.Addr().Network(), conf.addr.host, conf.addr.port)
	s.Infof("Press CTR^C to access the Slider Console")

	// Hold the execution until exit from the console
	wg := sync.WaitGroup{}
	wg.Add(1)
	// Capture Interrupt Signal to toggle log output and activate C2 Console
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for range sig {
			s.Logger.LogToBuffer()
			if out := s.NewConsole(); out == "bg" {
				s.Logger.BufferOut()
				s.Logger.LogToStdout()
			} else {
				_, _ = fmt.Print("\rTerminating Server...\n\n")
				break
			}
		}
		wg.Done()
	}()
	go func() {
		// TODO: net/http serve has no support for timeouts
		handler := http.Handler(http.HandlerFunc(s.handleHTTPClient))
		if err = http.Serve(l, handler); err != nil {
			s.Fatalf("%s", err)
		}
	}()

	wg.Wait()
}

func (s *server) listener(addr, port string) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("%s:%s", addr, port))
}

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
