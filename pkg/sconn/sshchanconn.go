package sconn

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type ChannelConn struct {
	ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (cc *ChannelConn) Network() string {
	return "tcp"
}

func (cc *ChannelConn) String() string {
	return ""
}

func (cc *ChannelConn) LocalAddr() net.Addr {
	if cc.localAddr == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}
	return cc.localAddr
}

func (cc *ChannelConn) RemoteAddr() net.Addr {
	if cc.remoteAddr == nil {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	}
	return cc.remoteAddr
}

func (cc *ChannelConn) SetDeadline(t time.Time) error {
	// SSH channels don't support deadlines, so we just ignore this
	return nil
}

func (cc *ChannelConn) SetReadDeadline(t time.Time) error {
	// SSH channels don't support deadlines, so we just ignore this
	return nil
}

func (cc *ChannelConn) SetWriteDeadline(t time.Time) error {
	// SSH channels don't support deadlines, so we just ignore this
	return nil
}

// SSHChannelToNetConn converts an SSH channel to a net.Conn interface
// This is used to adapt SSH channels to be used with code that expects net.Conn
func SSHChannelToNetConn(channel ssh.Channel) net.Conn {
	// Create default dummy addresses for the connection
	localAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
	remoteAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}

	return &ChannelConn{
		Channel:    channel,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
}
