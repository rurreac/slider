package server

import (
	"fmt"
	"slider/pkg/session"
	"slider/pkg/slog"
)

// checkDuplicateCallback checks if a callback connection from the same server already exists
// Uses peer server identity (fingerprint:port) from client-info exchange
func (s *server) checkDuplicateCallback(newSession *session.BidirectionalSession) error {
	// Get peer's server identity from the session (set during client-info exchange)
	peerIdentity := newSession.GetPeerIdentity()

	s.DebugWith("Checking for duplicate callback",
		slog.F("session_id", newSession.GetID()),
		slog.F("peer_identity", peerIdentity))

	if peerIdentity == "" {
		// Can't validate without identity - this shouldn't happen but handle gracefully
		s.DWarnWith("Cannot validate duplicate callback - no peer identity",
			slog.F("session_id", newSession.GetID()))
		return nil
	}

	s.sessionTrackMutex.Lock()
	defer s.sessionTrackMutex.Unlock()

	for _, sess := range s.sessionTrack.Sessions {
		if sess.GetID() == newSession.GetID() {
			continue // Skip self
		}

		// Check if there's ANY connection with the same peer identity
		// This catches both:
		// 1. Multiple callback connections (OperatorListener/AgentConnector)
		// 2. Mixed connections (e.g., OperationOperator then OperationCallback)
		existingIdentity := sess.GetPeerIdentity()
		if existingIdentity != "" && existingIdentity == peerIdentity {
			return fmt.Errorf("connection to/from %s already exists (session %d, role: %s)",
				peerIdentity, sess.GetID(), sess.GetRole().String())
		}
	}

	return nil
}
