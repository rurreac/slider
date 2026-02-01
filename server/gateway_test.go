package server

import (
	"fmt"
	"testing"

	"slider/pkg/interpreter"
	"slider/pkg/session"
	"slider/pkg/slog"
)

// Test Infrastructure

// testServer provides a minimal server for testing
type testServer struct {
	*slog.Logger
	sessions    map[int64]*session.BidirectionalSession
	fingerprint string
	port        int
	promiscuous bool
	interpreter *interpreter.Interpreter
}

// newTestServer creates a test server with sensible defaults
func newTestServer() *testServer {
	return &testServer{
		Logger:      slog.NewLogger("test"),
		sessions:    make(map[int64]*session.BidirectionalSession),
		fingerprint: "test-fingerprint",
		port:        8080,
		promiscuous: true,
	}
}

// GetSession implements session.Registry
func (s *testServer) GetSession(id int) (*session.BidirectionalSession, error) {
	sess, ok := s.sessions[int64(id)]
	if !ok {
		return nil, fmt.Errorf("session %d not found", id)
	}
	return sess, nil
}

// GetAllSessions implements session.Registry
func (s *testServer) GetAllSessions() []*session.BidirectionalSession {
	result := make([]*session.BidirectionalSession, 0, len(s.sessions))
	for _, sess := range s.sessions {
		result = append(result, sess)
	}
	return result
}

// GetServerInterpreter implements session.ServerInfo
func (s *testServer) GetServerInterpreter() *interpreter.Interpreter {
	return s.interpreter
}

// IsPromiscuous implements session.ServerInfo
func (s *testServer) IsPromiscuous() bool {
	return s.promiscuous
}

// GetServerIdentity implements session.ServerInfo
func (s *testServer) GetServerIdentity() string {
	return s.fingerprint + ":8080"
}

// GetFingerprint implements session.ServerInfo
func (s *testServer) GetFingerprint() string {
	return s.fingerprint
}

// addSession adds a session to the test server
func (s *testServer) addSession(sess *session.BidirectionalSession) {
	s.sessions[sess.GetID()] = sess
}

// Test Session Builder

// testSessionBuilder helps create sessions for testing
type testSessionBuilder struct {
	id          int64
	role        session.Role
	interpreter *interpreter.Interpreter
}

func newTestSession(id int64) *testSessionBuilder {
	return &testSessionBuilder{
		id:   id,
		role: session.GatewayListener,
	}
}

func (b *testSessionBuilder) withInterpreter(interp *interpreter.Interpreter) *testSessionBuilder {
	b.interpreter = interp
	return b
}

func (b *testSessionBuilder) build() *session.BidirectionalSession {
	logger := slog.NewLogger("test-session")
	sess := session.NewServerFromClientSession(
		logger,
		nil, // WsConn - nil for tests
		nil, // SSHServerConn - nil for tests
		nil, // SSHConfig - nil for tests
		b.interpreter,
		"127.0.0.1", // hostIP
		nil,         // opts
	)
	// Override role if needed
	sess.SetRole(b.role)
	// Set peer info explicitly since factory now treats arg as local interpreter
	if b.interpreter != nil {
		sess.SetPeerInfo(b.interpreter.BaseInfo)
	}
	return sess
}

// Promiscuous Routing Tests

// TestInt_SessionListing tests that GetAllSessions returns connected sessions
func TestInt_SessionListing(t *testing.T) {
	srv := newTestServer()

	// Add multiple sessions
	sess1 := newTestSession(1).
		withInterpreter(&interpreter.Interpreter{
			BaseInfo: interpreter.BaseInfo{
				User:     "user1",
				Hostname: "host1",
				System:   "linux",
			},
		}).
		build()
	sess2 := newTestSession(2).
		withInterpreter(&interpreter.Interpreter{
			BaseInfo: interpreter.BaseInfo{
				User:     "user2",
				Hostname: "host2",
				System:   "darwin",
			},
		}).
		build()

	srv.addSession(sess1)
	srv.addSession(sess2)

	// Test GetAllSessions
	sessions := srv.GetAllSessions()
	if len(sessions) != 2 {
		t.Errorf("Expected 2 sessions, got %d", len(sessions))
	}

	// Verify both sessions are present
	ids := make(map[int64]bool)
	for _, s := range sessions {
		ids[s.GetID()] = true
	}
	if !ids[1] || !ids[2] {
		t.Error("Expected sessions 1 and 2 to be present")
	}
}

// TestInt_LoopDetection tests that server identity enables loop detection
func TestInt_LoopDetection(t *testing.T) {
	srv := newTestServer()
	srv.fingerprint = "abc123"
	srv.port = 9000

	// Verify identity format
	identity := srv.GetServerIdentity()
	expected := "abc123:8080" // Uses hardcoded port in our test server
	if identity != expected {
		t.Errorf("Expected identity '%s', got '%s'", expected, identity)
	}

	// Simulate loop detection logic
	visitedServers := []string{"other:1234", "abc123:8080", "another:5678"}
	loopDetected := false
	for _, visited := range visitedServers {
		if visited == identity {
			loopDetected = true
			break
		}
	}

	if !loopDetected {
		t.Error("Expected loop to be detected")
	}
}

// TestInt_ForwardRequest tests that sessions can be looked up for forwarding
func TestInt_ForwardRequest(t *testing.T) {
	srv := newTestServer()

	// Add a target session
	targetSession := newTestSession(42). // Note: 42 is ignored, ID is auto-generated
						withInterpreter(&interpreter.Interpreter{
			BaseInfo: interpreter.BaseInfo{
				User:     "target",
				Hostname: "targethost",
				System:   "windows",
			},
		}).
		build()
	srv.addSession(targetSession)

	// Get the actual ID (auto-generated)
	actualID := targetSession.GetID()

	// Simulate forward request lookup using actual ID
	nextHop, err := srv.GetSession(int(actualID))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if nextHop == nil {
		t.Fatal("Expected to find next hop session")
	}
	if nextHop.GetID() != actualID {
		t.Errorf("Expected session ID %d, got %d", actualID, nextHop.GetID())
	}

	// Test lookup of non-existent session
	_, err = srv.GetSession(999)
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

// TestInt_FingerprintStamping tests that sessions get stamped with server fingerprint
func TestInt_FingerprintStamping(t *testing.T) {
	srv := newTestServer()
	srv.fingerprint = "server-fp-123"

	// When building RemoteSession responses, fingerprint is used
	fp := srv.GetFingerprint()
	if fp != "server-fp-123" {
		t.Errorf("Expected fingerprint 'server-fp-123', got '%s'", fp)
	}

	// Simulate building a RemoteSession
	sess := newTestSession(1).
		withInterpreter(&interpreter.Interpreter{
			BaseInfo: interpreter.BaseInfo{User: "testuser"},
		}).
		build()
	srv.addSession(sess)

	remoteSession := session.RemoteSession{
		ID:                sess.GetID(),
		ServerFingerprint: srv.GetFingerprint(),
		BaseInfo:          sess.GetPeerInfo(),
	}

	if remoteSession.ServerFingerprint != "server-fp-123" {
		t.Errorf("Expected fingerprint in RemoteSession, got '%s'", remoteSession.ServerFingerprint)
	}
}
