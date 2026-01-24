package server

import (
	"testing"

	"slider/pkg/interpreter"
	"slider/pkg/session"
	"slider/pkg/slog"
)

// ========================================
// General Server Tests
// ========================================

// TestInt_ClientInfoExchange tests that interpreter info is stored after handshake
func TestInt_ClientInfoExchange(t *testing.T) {
	// Create a session with interpreter info (simulating post-handshake state)
	interp := &interpreter.Interpreter{
		BaseInfo: interpreter.BaseInfo{
			User:      "testuser",
			Hostname:  "testhost",
			System:    "linux",
			Arch:      "amd64",
			HomeDir:   "/home/testuser",
			SliderDir: "/opt/slider",
			LaunchDir: "/tmp",
		},
	}

	logger := slog.NewLogger("test-session")
	sess := session.NewServerFromClientSession(
		logger,
		nil,    // WsConn
		nil,    // SSHServerConn
		nil,    // SSHConfig
		interp, // Passed as local interpreter
		"192.168.1.100",
		nil, // opts
	)
	// Explicitly set peer info for test
	sess.SetPeerInfo(interp.BaseInfo)

	// Verify interpreter info is stored correctly
	storedInterp := sess.GetPeerInfo()
	if storedInterp.User == "" {
		t.Fatal("Expected user to be set")
	}

	if storedInterp.User != "testuser" {
		t.Errorf("Expected user 'testuser', got '%s'", storedInterp.User)
	}
	if storedInterp.Hostname != "testhost" {
		t.Errorf("Expected hostname 'testhost', got '%s'", storedInterp.Hostname)
	}
	if storedInterp.System != "linux" {
		t.Errorf("Expected system 'linux', got '%s'", storedInterp.System)
	}
	if storedInterp.Arch != "amd64" {
		t.Errorf("Expected arch 'amd64', got '%s'", storedInterp.Arch)
	}
}

// TestInt_SessionCleanup tests that sessions are properly removed after close
func TestInt_SessionCleanup(t *testing.T) {
	srv := newTestServer()

	// Create and add a session
	logger := slog.NewLogger("test-cleanup")
	sess := session.NewServerFromClientSession(
		logger,
		nil, nil, nil,
		&interpreter.Interpreter{
			BaseInfo: interpreter.BaseInfo{User: "cleanup-test"},
		},
		"127.0.0.1",
		nil,
	)
	srv.addSession(sess)
	sessionID := sess.GetID()

	// Verify session is present
	if len(srv.sessions) != 1 {
		t.Fatalf("Expected 1 session, got %d", len(srv.sessions))
	}

	// Simulate session removal (what dropWebSocketSession does)
	delete(srv.sessions, sessionID)

	// Verify session is removed
	if len(srv.sessions) != 0 {
		t.Errorf("Expected 0 sessions after cleanup, got %d", len(srv.sessions))
	}

	// Verify lookup returns error
	_, err := srv.GetSession(int(sessionID))
	if err == nil {
		t.Error("Expected error when looking up removed session")
	}
}

// TestInt_RoleBasedAccess tests that role guards work correctly
func TestInt_RoleBasedAccess(t *testing.T) {
	// Test role creation and validation
	tests := []struct {
		name        string
		role        session.Role
		isOperator  bool
		isGateway   bool
		isAgent     bool
		isConnector bool
	}{
		{
			name:        "OperatorConnector",
			role:        session.OperatorConnector,
			isOperator:  true,
			isGateway:   false,
			isAgent:     false,
			isConnector: true,
		},
		{
			name:        "OperatorListener",
			role:        session.OperatorListener,
			isOperator:  true,
			isGateway:   false,
			isAgent:     false,
			isConnector: false,
		},
		{
			name:        "GatewayConnector",
			role:        session.GatewayConnector,
			isOperator:  false,
			isGateway:   true,
			isAgent:     false,
			isConnector: true,
		},
		{
			name:        "GatewayListener",
			role:        session.GatewayListener,
			isOperator:  false,
			isGateway:   true,
			isAgent:     false,
			isConnector: false,
		},
		{
			name:        "AgentConnector",
			role:        session.AgentConnector,
			isOperator:  false,
			isGateway:   false,
			isAgent:     true,
			isConnector: true,
		},
		{
			name:        "AgentListener",
			role:        session.AgentListener,
			isOperator:  false,
			isGateway:   false,
			isAgent:     true,
			isConnector: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.role.IsOperator() != tc.isOperator {
				t.Errorf("IsOperator: expected %v, got %v", tc.isOperator, tc.role.IsOperator())
			}
			if tc.role.IsGateway() != tc.isGateway {
				t.Errorf("IsGateway: expected %v, got %v", tc.isGateway, tc.role.IsGateway())
			}
			if tc.role.IsAgent() != tc.isAgent {
				t.Errorf("IsAgent: expected %v, got %v", tc.isAgent, tc.role.IsAgent())
			}
			if tc.role.IsConnector() != tc.isConnector {
				t.Errorf("IsConnector: expected %v, got %v", tc.isConnector, tc.role.IsConnector())
			}
		})
	}
}

// TestInt_SessionActivation tests session active state management
func TestInt_SessionActivation(t *testing.T) {
	logger := slog.NewLogger("test-activation")
	sess := session.NewServerFromClientSession(
		logger,
		nil, nil, nil,
		&interpreter.Interpreter{
			BaseInfo: interpreter.BaseInfo{User: "active-test"},
		},
		"127.0.0.1",
		nil,
	)

	// New session should be active
	if !sess.IsActive() {
		t.Error("Expected new session to be active")
	}

	// After close, session should be inactive
	_ = sess.Close()
	if sess.IsActive() {
		t.Error("Expected closed session to be inactive")
	}
}
