package instance

import "golang.org/x/crypto/ssh"

// ChannelOpener defines the interface required to open channels and send requests
// This allows abstracting specific SSH connections (like direct ssh.Conn or our custom RemoteConnection)
type ChannelOpener interface {
	OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
}
