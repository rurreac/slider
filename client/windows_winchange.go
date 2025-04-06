//go:build windows

package client

import "slider/pkg/conf"

func (s *Session) updatePtySize(termSize conf.TermDimensions) {
	if sizeErr := s.interpreter.Pty.Resize(int(termSize.Width), int(termSize.Height)); sizeErr != nil {
		s.Logger.Errorf("%s%v", sizeErr, s.logID)
	}
}
