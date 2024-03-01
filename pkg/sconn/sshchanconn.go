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
	return cc.localAddr
}

func (cc *ChannelConn) RemoteAddr() net.Addr {
	return cc.remoteAddr
}

func (cc *ChannelConn) SetDeadline(t time.Time) error {
	return nil
}

func (cc *ChannelConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (cc *ChannelConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func SSHChannelToNetConn(channel ssh.Channel) net.Conn {
	return &ChannelConn{
		Channel: channel,
	}
}
