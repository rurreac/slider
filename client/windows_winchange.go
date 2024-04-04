//go:build windows

package client

func (s *Session) updatePtySize(rows int, cols int) {
	if sizeErr := s.interpreter.Pty.Resize(cols, rows); sizeErr != nil {
		s.Logger.Errorf("%s%v", sizeErr, s.logID)
	}
}
