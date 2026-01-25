package interpreter

import "io"

// BaseInfo contains common system information shared between
// local Interpreter and RemoteSession.
type BaseInfo struct {
	Arch      string `json:"Arch"`
	System    string `json:"System"`
	User      string `json:"User"`
	HomeDir   string `json:"HomeDir"`
	Hostname  string `json:"Hostname"`
	PtyOn     bool   `json:"PtyOn"`
	ColorOn   bool   `json:"ColorOn"`
	SliderDir string `json:"SliderDir"`
	LaunchDir string `json:"LaunchDir"`
}

// Info contains the basic information a remote needs from the peer
type Info struct {
	BaseInfo
	Identity string `json:"identity,omitempty"` // Server identity (fingerprint:port), optional
}

// Pty defines a platform-independent interface for PTY operations
type Pty interface {
	io.ReadWriteCloser
	Resize(cols, rows uint32) error
	Wait() error
}
