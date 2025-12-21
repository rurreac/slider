package socks

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"slider/pkg/sio"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// Client represents a SOCKS5 client that connects through an SSH channel
type Client struct {
	logger    *slog.Logger
	sessionID int64
	opener    ChannelOpener
}

// ChannelOpener defines the interface for opening SSH channels
type ChannelOpener interface {
	OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error)
}

// NewClient creates a new SOCKS5 client
func NewClient(logger *slog.Logger, sessionID int64, opener ChannelOpener) *Client {
	return &Client{
		logger:    logger,
		sessionID: sessionID,
		opener:    opener,
	}
}

// Type returns the service type identifier
func (c *Client) Type() string {
	return "socks"
}

// Start implements the Service interface - handles a SOCKS connection
func (c *Client) Start(conn net.Conn) error {
	return c.HandleConnection(conn)
}

// Stop implements the Service interface - currently no cleanup needed
func (c *Client) Stop() error {
	// SOCKS client doesn't maintain persistent state that needs cleanup
	return nil
}

// HandleConnection handles a SOCKS connection by opening an SSH channel and piping data
func (c *Client) HandleConnection(conn net.Conn) error {
	defer func() { _ = conn.Close() }()

	socksChan, reqs, oErr := c.opener.OpenChannel("socks5", nil)
	if oErr != nil {
		c.logger.ErrorWith("Failed to open \"socks5\" channel",
			slog.F("session_id", c.sessionID),
			slog.F("err", oErr))
		return oErr
	}
	defer func() { _ = socksChan.Close() }()
	go ssh.DiscardRequests(reqs)

	_, _ = sio.PipeWithCancel(socksChan, conn)
	return nil
}

// ConnectViaSocks establishes a connection to a destination through a SOCKS5 proxy
// This is used for direct-tcpip channel handling
func (c *Client) ConnectViaSocks(destination types.TcpIpChannelMsg, clientChannel ssh.Channel) error {
	// Open a SOCKS5 channel to the client
	socksChannel, socksRequests, oErr := c.opener.OpenChannel("socks5", nil)
	if oErr != nil {
		return fmt.Errorf("could not open socks5 channel - %v", oErr)
	}
	defer func() { _ = socksChannel.Close() }()

	// Discard the SSH requests from the socks channel
	go ssh.DiscardRequests(socksRequests)

	// Perform SOCKS5 handshake
	if err := c.performHandshake(socksChannel, destination); err != nil {
		return err
	}

	// Connection established, log it
	c.logger.DebugWith("connection established to destination via SOCKS",
		slog.F("session_id", c.sessionID),
		slog.F("dst_host", destination.DstHost),
		slog.F("dst_port", destination.DstPort))

	// Pipe data between the channels
	_, _ = sio.PipeWithCancel(clientChannel, socksChannel)

	return nil
}

// performHandshake performs a SOCKS5 handshake following RFC1928
func (c *Client) performHandshake(socksChannel io.ReadWriter, destination types.TcpIpChannelMsg) error {
	// Start with SOCKS5 handshake:
	// - protocol version (5) +
	// - number of authentication methods +
	// - auth (0 for no auth)
	_, _ = socksChannel.Write([]byte{0x05, 0x01, 0x00})

	// Read the server response
	respBuf := make([]byte, 2)
	_, err := socksChannel.Read(respBuf)
	if err != nil {
		return fmt.Errorf("could not read socks5 handshake response - %v", err)
	}

	// Answer must be:
	// - protocol version (5) +
	// - success (0)
	if respBuf[0] != 0x05 || respBuf[1] != 0x00 {
		return fmt.Errorf("invalid socks5 handshake response - %v", respBuf)
	}

	// Send connect request to the destination:
	// - protocol version (5) +
	// - connect command (1) +
	// - RSV (reserved) +
	// - ATYP (address type of following address, assumes "domainname" 3)
	// - destination host
	// - destination port (2 bytes length)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(destination.DstHost))}
	req = append(req, []byte(destination.DstHost)...)

	// Add port in network byte order (big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(destination.DstPort))
	req = append(req, portBytes...)

	// Send connect request
	_, err = socksChannel.Write(req)
	if err != nil {
		return fmt.Errorf("could not write socks5 handshake connect request - %v", err)
	}

	// Read connect response
	respHdr := make([]byte, 4)
	_, err = socksChannel.Read(respHdr)
	if err != nil {
		return fmt.Errorf("could not read socks5 handshake connect response - %v", err)
	}

	// Check if connection was successful:
	// - socks version (5) +
	// - success (0)
	if respHdr[0] != 0x05 || respHdr[1] != 0x00 {
		return fmt.Errorf("unsuccessful socks5 handshake response - %v", respHdr)
	}

	// Read the rest of the response based on address type
	var respBodyLen int
	switch respHdr[3] {
	// IPv4 address
	case 0x01:
		// 4 bytes IPv4 + 2 bytes port
		respBodyLen = 4 + 2
	// Domain name
	case 0x03:
		domainLen := make([]byte, 1)
		_, _ = socksChannel.Read(domainLen)
		// domain length + 2 bytes port
		respBodyLen = int(domainLen[0]) + 2
	// IPv6 address
	case 0x04:
		// 16 bytes IPv6 + 2 bytes port
		respBodyLen = 16 + 2
	default:
		return fmt.Errorf("unknown address type \"%v\" socks5 handshake response", respHdr[3])
	}

	// Read the destination host + port
	respBody := make([]byte, respBodyLen)
	_, err = socksChannel.Read(respBody)
	if err != nil {
		return fmt.Errorf("could not read destination from socks5 handshake response - %v", err)
	}

	return nil
}
