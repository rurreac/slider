//go:build !windows

package client

import "github.com/creack/pty"

func (c *client) updatePtySize(rows int, cols int) {
	if sizeErr := pty.Setsize(c.interpreter.Pty, &pty.Winsize{
		Rows: uint16(rows),
		Cols: uint16(cols),
	}); sizeErr != nil {
		c.Errorf("%s", sizeErr)
	}
}
