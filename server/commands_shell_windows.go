//go:build windows

package server

import "net"

// CaptureInterrupts - Windows doesn't support syscall interrupts
func (ic *InteractiveConsole) CaptureInterrupts(_ net.Conn) {}
