package instance

import (
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/ssh"
	"slider/pkg/types"
)

type socksConfig struct {
	sessionClientChannel ssh.Channel
	socksChannel         ssh.Channel
	directTCPIP          types.TcpIpChannelMsg
}

// handshake performs a SOCKS 5 handshake following the RFC1928
func (sc *socksConfig) handshake() (bool, error) {
	// Start with SOCKS5 handshake:
	// - protocol version (5) +
	// - number of authentication methods +
	// - auth (0 for no auth)
	_, _ = sc.socksChannel.Write([]byte{0x05, 0x01, 0x00})

	// Read the server response
	respBuf := make([]byte, 2)
	_, err := sc.socksChannel.Read(respBuf)
	if err != nil {
		return false, fmt.Errorf("could not read socks5 handshake response - %v", err)
	}

	// Answer must be:
	// - protocol version (5) +
	// - success (0)
	if respBuf[0] != 0x05 || respBuf[1] != 0x00 {
		return false, fmt.Errorf("invalid socks5 handshake response - %v", respBuf)
	}

	// Send connect request to the destination:
	// - protocol version (5) +
	// - connect command (1) +
	// - RSV (reserved) +
	// - ATYP (address type of following address, assumes "domainname" 3)
	// - destination host
	// - destination port (2 bytes length)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(sc.directTCPIP.DstHost))}
	req = append(req, []byte(sc.directTCPIP.DstHost)...)

	// Add port in network byte order (big endian)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(sc.directTCPIP.DstPort))
	req = append(req, portBytes...)

	// Send connect request
	_, err = sc.socksChannel.Write(req)
	if err != nil {
		return false, fmt.Errorf("could not write socks5 handshake connect request - %v", err)
	}

	// Read connect response
	respHdr := make([]byte, 4)
	_, err = sc.socksChannel.Read(respHdr)
	if err != nil {
		return false, fmt.Errorf("could not read socks5 handshake connect response - %v", err)
	}

	// Check if connection was successful:
	// - socks version (5) +
	// - success (0)
	if respHdr[0] != 0x05 || respHdr[1] != 0x00 {
		return false, fmt.Errorf("unsuccesful socks5 handshake response - %v", respHdr)
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
		_, _ = sc.socksChannel.Read(domainLen)
		// domain length + 2 bytes port
		respBodyLen = int(domainLen[0]) + 2
	// IPv6 address
	case 0x04:
		// 16 bytes IPv6 + 2 bytes port
		respBodyLen = 16 + 2
	default:
		return false, fmt.Errorf("unknown address type \"%v\" socks5 handshake response", respHdr[3])
	}

	// Read the destination host + port
	respBody := make([]byte, respBodyLen)
	_, err = sc.socksChannel.Read(respBody)
	if err != nil {
		return false, fmt.Errorf("could not read destination from socks5 handshake response - %v", err)
	}

	return true, nil
}
