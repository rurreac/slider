//go:build !windows

package client

import "github.com/creack/pty"

func (s *Session) updatePtySize(rows int, cols int) {
	if sizeErr := pty.Setsize(s.interpreter.Pty, &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
		X:    uint16(cols),
		Y:    uint16(rows),
	}); sizeErr != nil {
		s.Errorf("%s%v", s.logID, sizeErr)
	}
}
