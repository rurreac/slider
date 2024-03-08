//go:build windows

package client

func (c *client) updatePtySize(rows int, cols int) {
	if sizeErr := c.interpreter.Pty.Resize(cols, rows); sizeErr != nil {
		c.Errorf("%v", sizeErr)
	}
}
