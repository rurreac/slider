package session

import (
	"errors"
	"testing"

	"slider/pkg/interpreter"
	"slider/pkg/slog"
)

// ========================================
// Mock ApplicationServer for Testing
// ========================================

// MockApplicationServer provides a testable implementation of ApplicationServer
type MockApplicationServer struct {
	sessions    []*BidirectionalSession
	fingerprint string
	identity    string
	gateway     bool
	interpreter *interpreter.Interpreter

	// Track method calls for assertions
	GetSessionCalls     []int
	GetAllSessionsCalls int
}

// NewMockApplicationServer creates a new mock with sensible defaults
func NewMockApplicationServer() *MockApplicationServer {
	return &MockApplicationServer{
		sessions:    make([]*BidirectionalSession, 0),
		fingerprint: "test-fingerprint",
		identity:    "test-fingerprint:8080",
		gateway:     true,
	}
}

// GetSession implements Registry
func (m *MockApplicationServer) GetSession(id int) (*BidirectionalSession, error) {
	m.GetSessionCalls = append(m.GetSessionCalls, id)
	for _, sess := range m.sessions {
		if sess.GetID() == int64(id) {
			return sess, nil
		}
	}
	return nil, errors.New("session not found")
}

// GetAllSessions implements Registry
func (m *MockApplicationServer) GetAllSessions() []*BidirectionalSession {
	m.GetAllSessionsCalls++
	return m.sessions
}

// GetServerInterpreter implements ServerInfo
func (m *MockApplicationServer) GetServerInterpreter() *interpreter.Interpreter {
	return m.interpreter
}

// IsGateway implements ServerInfo
func (m *MockApplicationServer) IsGateway() bool {
	return m.gateway
}

// GetServerIdentity implements ServerInfo
func (m *MockApplicationServer) GetServerIdentity() string {
	return m.identity
}

// GetFingerprint implements ServerInfo
func (m *MockApplicationServer) GetFingerprint() string {
	return m.fingerprint
}

// AddSession adds a session to the mock
func (m *MockApplicationServer) AddSession(sess *BidirectionalSession) {
	m.sessions = append(m.sessions, sess)
}

// ========================================
// Test Session Builder
// ========================================

// SessionBuilder helps create BidirectionalSession instances for testing
type SessionBuilder struct {
	session *BidirectionalSession
}

// NewTestSession creates a builder for test sessions
func NewTestSession(id int64) *SessionBuilder {
	logger := slog.NewLogger("test")
	return &SessionBuilder{
		session: &BidirectionalSession{
			sessionID:     id,
			role:          GatewayListener,
			peerRole:      OperatorConnector,
			logger:        logger,
			revPortFwdMap: make(map[uint32]*RevPortControl),
			active:        true,
		},
	}
}

// WithRole sets the session role
func (b *SessionBuilder) WithRole(role Role) *SessionBuilder {
	b.session.role = role
	return b
}

// WithPeerRole sets the peer role
func (b *SessionBuilder) WithPeerRole(role Role) *SessionBuilder {
	b.session.peerRole = role
	return b
}

// WithApplicationServer injects the application server
func (b *SessionBuilder) WithApplicationServer(srv ApplicationServer) *SessionBuilder {
	b.session.applicationServer = srv
	return b
}

// WithInterpreter sets the peer interpreter
func (b *SessionBuilder) WithInterpreter(interp *interpreter.Interpreter) *SessionBuilder {
	b.session.peerInterpreter = interp
	return b
}

// WithGateway sets the gateway flag
func (b *SessionBuilder) WithGateway(gateway bool) *SessionBuilder {
	b.session.isGateway = gateway
	return b
}

// Build returns the constructed session
func (b *SessionBuilder) Build() *BidirectionalSession {
	return b.session
}

// ========================================
// Example Tests
// ========================================

func TestMockApplicationServer_GetSession(t *testing.T) {
	// Create mock server
	mock := NewMockApplicationServer()

	// Add a test session
	testSession := NewTestSession(42).Build()
	mock.AddSession(testSession)

	// Test GetSession
	found, err := mock.GetSession(42)
	if err != nil {
		t.Fatalf("Expected to find session 42, got error: %v", err)
	}
	if found.GetID() != 42 {
		t.Errorf("Expected session ID 42, got %d", found.GetID())
	}

	// Test GetSession with non-existent ID
	_, err = mock.GetSession(999)
	if err == nil {
		t.Error("Expected error for non-existent session")
	}

	// Verify call tracking
	if len(mock.GetSessionCalls) != 2 {
		t.Errorf("Expected 2 GetSession calls, got %d", len(mock.GetSessionCalls))
	}
}

func TestMockApplicationServer_GetAllSessions(t *testing.T) {
	mock := NewMockApplicationServer()

	// Add multiple sessions
	mock.AddSession(NewTestSession(1).Build())
	mock.AddSession(NewTestSession(2).Build())
	mock.AddSession(NewTestSession(3).Build())

	// Test GetAllSessions
	sessions := mock.GetAllSessions()
	if len(sessions) != 3 {
		t.Errorf("Expected 3 sessions, got %d", len(sessions))
	}

	// Verify call tracking
	if mock.GetAllSessionsCalls != 1 {
		t.Errorf("Expected 1 GetAllSessions call, got %d", mock.GetAllSessionsCalls)
	}
}

func TestMockApplicationServer_ServerInfo(t *testing.T) {
	mock := NewMockApplicationServer()
	mock.fingerprint = "abc123"
	mock.identity = "abc123:9000"
	mock.gateway = true

	if mock.GetFingerprint() != "abc123" {
		t.Errorf("Expected fingerprint 'abc123', got '%s'", mock.GetFingerprint())
	}
	if mock.GetServerIdentity() != "abc123:9000" {
		t.Errorf("Expected identity 'abc123:9000', got '%s'", mock.GetServerIdentity())
	}
	if !mock.IsGateway() {
		t.Error("Expected gateway to be true")
	}
}

func TestSessionBuilder(t *testing.T) {
	mock := NewMockApplicationServer()

	session := NewTestSession(100).
		WithRole(AgentListener).
		WithPeerRole(OperatorConnector).
		WithApplicationServer(mock).
		WithGateway(true).
		Build()

	if session.GetID() != 100 {
		t.Errorf("Expected ID 100, got %d", session.GetID())
	}
	if session.GetRole() != AgentListener {
		t.Errorf("Expected role AgentListener, got %s", session.GetRole())
	}
	if session.GetPeerRole() != OperatorConnector {
		t.Errorf("Expected peer role OperatorConnector, got %s", session.GetPeerRole())
	}
	if !session.GetIsGateway() {
		t.Error("Expected gateway to be true")
	}
}

// TestHandleSliderSessions_LoopDetectionLogic tests loop detection logic
// Note: We can't easily test the full handler because ssh.Request.Reply
// requires a real SSH connection. This test validates the detection logic works.
func TestHandleSliderSessions_LoopDetectionLogic(t *testing.T) {
	mock := NewMockApplicationServer()
	mock.identity = "server1:8080"

	// Create session with mock server
	session := NewTestSession(1).
		WithRole(GatewayListener).
		WithApplicationServer(mock).
		Build()

	// Verify the session can access server identity for loop detection
	identity := session.applicationServer.GetServerIdentity()
	if identity != "server1:8080" {
		t.Errorf("Expected identity 'server1:8080', got '%s'", identity)
	}

	// Simulate loop detection logic (extracted from handler)
	visited := []string{"other-server:9000", "server1:8080"}
	detected := false
	for _, v := range visited {
		if v == identity {
			detected = true
			break
		}
	}
	if !detected {
		t.Error("Expected loop to be detected")
	}
}

// TestSessionGathering_DataProviderPattern tests that the data provider pattern works
func TestSessionGathering_DataProviderPattern(t *testing.T) {
	mock := NewMockApplicationServer()
	mock.identity = "server1:8080"
	mock.fingerprint = "fp1"

	// Add sessions to mock
	session1 := NewTestSession(1).Build()
	session2 := NewTestSession(2).
		WithInterpreter(&interpreter.Interpreter{
			User:     "testuser",
			Hostname: "testhost",
			System:   "linux",
			Arch:     "amd64",
		}).
		Build()

	mock.AddSession(session1)
	mock.AddSession(session2)

	// Create a session that would call GetAllSessions
	requestingSession := NewTestSession(100).
		WithRole(GatewayListener).
		WithApplicationServer(mock).
		Build()

	// Verify the session can access all sessions via the interface
	sessions := requestingSession.applicationServer.GetAllSessions()
	if len(sessions) != 2 {
		t.Errorf("Expected 2 sessions, got %d", len(sessions))
	}

	// Verify GetFingerprint works
	fp := requestingSession.applicationServer.GetFingerprint()
	if fp != "fp1" {
		t.Errorf("Expected fingerprint 'fp1', got '%s'", fp)
	}

	// Verify call tracking
	if mock.GetAllSessionsCalls != 1 {
		t.Errorf("Expected 1 GetAllSessions call, got %d", mock.GetAllSessionsCalls)
	}
}

// TestSessionLookup tests the GetSession data provider method
func TestSessionLookup(t *testing.T) {
	mock := NewMockApplicationServer()

	// Add a session
	session := NewTestSession(42).
		WithInterpreter(&interpreter.Interpreter{
			User:   "admin",
			System: "darwin",
		}).
		Build()
	mock.AddSession(session)

	// Create a requesting session
	requestingSession := NewTestSession(1).
		WithApplicationServer(mock).
		Build()

	// Look up the session via the interface
	found, err := requestingSession.applicationServer.GetSession(42)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if found.GetID() != 42 {
		t.Errorf("Expected session ID 42, got %d", found.GetID())
	}
	if found.GetInterpreter().User != "admin" {
		t.Errorf("Expected user 'admin', got '%s'", found.GetInterpreter().User)
	}

	// Try to look up non-existent session
	_, err = requestingSession.applicationServer.GetSession(999)
	if err == nil {
		t.Error("Expected error for non-existent session")
	}
}

// TestRemoteSessionBuilding tests building RemoteSession structs
func TestRemoteSessionBuilding(t *testing.T) {
	// This simulates what handleSliderSessions does when building responses
	mock := NewMockApplicationServer()
	mock.fingerprint = "server-fp"

	session := NewTestSession(1).
		WithInterpreter(&interpreter.Interpreter{
			User:      "testuser",
			Hostname:  "testhost",
			System:    "linux",
			Arch:      "amd64",
			HomeDir:   "/home/test",
			SliderDir: "/opt/slider",
			LaunchDir: "/tmp",
		}).
		Build()

	mock.AddSession(session)

	// Build RemoteSession (simulating handler logic)
	sessions := mock.GetAllSessions()
	var remoteSessions []RemoteSession
	for _, sess := range sessions {
		interp := sess.GetInterpreter()
		remoteSessions = append(remoteSessions, RemoteSession{
			ID:                sess.GetID(),
			ServerFingerprint: mock.GetFingerprint(),
			User:              interp.User,
			Host:              interp.Hostname,
			System:            interp.System,
			Arch:              interp.Arch,
			HomeDir:           interp.HomeDir,
			SliderDir:         interp.SliderDir,
			LaunchDir:         interp.LaunchDir,
		})
	}

	if len(remoteSessions) != 1 {
		t.Fatalf("Expected 1 remote session, got %d", len(remoteSessions))
	}

	rs := remoteSessions[0]
	if rs.ID != 1 {
		t.Errorf("Expected ID 1, got %d", rs.ID)
	}
	if rs.ServerFingerprint != "server-fp" {
		t.Errorf("Expected fingerprint 'server-fp', got '%s'", rs.ServerFingerprint)
	}
	if rs.User != "testuser" {
		t.Errorf("Expected user 'testuser', got '%s'", rs.User)
	}
	if rs.System != "linux" {
		t.Errorf("Expected system 'linux', got '%s'", rs.System)
	}
}
