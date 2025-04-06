//go:build !windows

package client

import (
	"github.com/creack/pty"
	"slider/pkg/conf"
)

func (s *Session) updatePtySize(termSize conf.TermDimensions) {
	if sizeErr := pty.Setsize(
		s.interpreter.Pty, &pty.Winsize{
			Rows: uint16(termSize.Height),
			Cols: uint16(termSize.Width),
			X:    uint16(termSize.X),
			Y:    uint16(termSize.Y),
		},
	); sizeErr != nil {
		s.Logger.Errorf("%s%v", s.logID, sizeErr)
	}
}
