//go:build !windows

package client

import "github.com/creack/pty"

func (s *Session) updatePtySize(rows int, cols int) {
	if sizeErr := pty.Setsize(s.interpreter.Pty, &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	}); sizeErr != nil {
		s.Errorf("%v", sizeErr)
	}
}
