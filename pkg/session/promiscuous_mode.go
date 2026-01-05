package session

import (
	"encoding/json"
	"fmt"
	"sort"

	"slider/pkg/slog"
)

// ========================================
// Promiscuous Mode Methods
// ========================================

// Methods specific to PromiscuousRole

// SetRouter sets the channel router (can be *Router or *remote.Router)
func (s *BidirectionalSession) SetRouter(router interface{}) {
	s.sessionMutex.Lock()
	s.router = router
	s.sessionMutex.Unlock()
}

// GetRouter returns the channel router (can be *Router or *remote.Router)
func (s *BidirectionalSession) GetRouter() interface{} {
	return s.router
}

// SetApplicationServer sets the application server for slider-connect delegation
func (s *BidirectionalSession) SetApplicationServer(server ApplicationServer) {
	s.sessionMutex.Lock()
	s.applicationServer = server
	s.sessionMutex.Unlock()
}

// GetApplicationServer returns the application server
func (s *BidirectionalSession) GetApplicationServer() ApplicationServer {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.applicationServer
}

// SetRequestHandler sets the application request handler
func (s *BidirectionalSession) SetRequestHandler(handler interface{}) {
	s.sessionMutex.Lock()
	s.requestHandler = handler
	s.sessionMutex.Unlock()
}

// GetRequestHandler returns the application request handler
func (s *BidirectionalSession) GetRequestHandler() interface{} {
	s.sessionMutex.Lock()
	defer s.sessionMutex.Unlock()
	return s.requestHandler
}

// AddRemoteSession registers a remote session (PromiscuousRole only)
func (s *BidirectionalSession) AddRemoteSession(key string, rs RemoteSession) {
	s.remoteSessionsMutex.Lock()
	defer s.remoteSessionsMutex.Unlock()
	s.remoteSessions[key] = rs

	s.logger.DebugWith("Remote session added",
		slog.F("session_id", s.sessionID),
		slog.F("remote_key", key),
		slog.F("remote_session_id", rs.ID))
}

// GetRemoteSession retrieves a remote session
func (s *BidirectionalSession) GetRemoteSession(key string) (RemoteSession, bool) {
	s.remoteSessionsMutex.RLock()
	defer s.remoteSessionsMutex.RUnlock()
	rs, exists := s.remoteSessions[key]
	return rs, exists
}

// RemoveRemoteSession unregisters a remote session
func (s *BidirectionalSession) RemoveRemoteSession(key string) {
	s.remoteSessionsMutex.Lock()
	defer s.remoteSessionsMutex.Unlock()
	delete(s.remoteSessions, key)

	s.logger.DebugWith("Remote session removed",
		slog.F("session_id", s.sessionID),
		slog.F("remote_key", key))
}

// GetRemoteSessionsSorted returns all tracked remote sessions sorted by ID and path
func (s *BidirectionalSession) GetRemoteSessionsSorted() []RemoteSession {
	s.remoteSessionsMutex.RLock()
	defer s.remoteSessionsMutex.RUnlock()

	sessions := make([]RemoteSession, 0, len(s.remoteSessions))
	for _, rs := range s.remoteSessions {
		sessions = append(sessions, rs)
	}

	// Sort sessions by ID then by Path length/content to ensure deterministic order
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].ID != sessions[j].ID {
			return sessions[i].ID < sessions[j].ID
		}
		// Same ID, compare path
		if len(sessions[i].Path) != len(sessions[j].Path) {
			return len(sessions[i].Path) < len(sessions[j].Path)
		}
		for k := range sessions[i].Path {
			if sessions[i].Path[k] != sessions[j].Path[k] {
				return sessions[i].Path[k] < sessions[j].Path[k]
			}
		}
		return false
	})

	return sessions
}

// GetRemoteSessionsRequest represents a request for remote sessions
type GetRemoteSessionsRequest struct {
	Visited []string `json:"visited"`
}

// GetRemoteSessions fetches sessions from connected servers (recursive)
func (s *BidirectionalSession) GetRemoteSessions(visited []string) ([]RemoteSession, error) {
	if s.role != PromiscuousRole {
		return nil, fmt.Errorf("remote sessions only available in promiscuous mode")
	}

	s.sessionMutex.Lock()
	client := s.sshClient
	s.sessionMutex.Unlock()

	if client == nil {
		return nil, fmt.Errorf("no active ssh client connection")
	}

	req := GetRemoteSessionsRequest{
		Visited: visited,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send a specific request to the server to get sessions
	ok, resPayload, err := client.SendRequest("slider-sessions", true, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to send slider-sessions request: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("server rejected slider-sessions request")
	}

	var sessions []RemoteSession
	if err := json.Unmarshal(resPayload, &sessions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal sessions: %w", err)
	}

	return sessions, nil
}

// HandleSessionsRequest responds to slider-sessions requests
// This is called when another server asks this promiscuous session for its connected sessions
func (s *BidirectionalSession) HandleSessionsRequest(payload []byte) ([]RemoteSession, error) {
	// Parse the request
	var request GetRemoteSessionsRequest
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &request); err != nil {
			return nil, fmt.Errorf("failed to unmarshal request: %w", err)
		}
	}

	s.logger.DebugWith("Handling sessions request",
		slog.F("session_id", s.sessionID),
		slog.F("visited_count", len(request.Visited)))

	// Collect all remote sessions
	sessions := s.GetRemoteSessionsSorted()

	return sessions, nil
}
