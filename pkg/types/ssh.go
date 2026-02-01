package types

import "golang.org/x/crypto/ssh"

// PtyRequest is the structure of an SSH_MSG_CHANNEL_REQUEST
// "pty-req" as described in RFC4254
// https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
type PtyRequest struct {
	TermEnvVar       string
	TermWidthCols    uint32
	TermHeightRows   uint32
	TermWidthPixels  uint32
	TermHeightPixels uint32
	TerminalModes    string
}

// TcpIpChannelMsg is the structure of an SSH_MSG_CHANNEL_OPEN
// "direct-tcpip" and "forwarded-tcpip", as described in RFC4254
// https://datatracker.ietf.org/doc/html/rfc4254#section-7.2
type TcpIpChannelMsg struct {
	DstHost string
	DstPort uint32
	SrcHost string
	SrcPort uint32
}

// TcpIpFwdRequest is the structure of an SSH_MSG_GLOBAL_REQUEST
// as described in RFC4254
// https://datatracker.ietf.org/doc/html/rfc4254#section-7.1
type TcpIpFwdRequest struct {
	BindAddress string
	BindPort    uint32
}

// TcpIpReqSuccess is the structure of an SSH_MSG_REQUEST_SUCCESS
// as described in RFC4254
// https://datatracker.ietf.org/doc/html/rfc4254#section-6.2
type TcpIpReqSuccess struct {
	BoundPort uint32
}

// CustomTcpIpChannelMsg is a wrapper for TcpIpChannelMsg to include the channel
type CustomTcpIpChannelMsg struct {
	Protocol  string
	IsSshConn bool
	*TcpIpChannelMsg
	Channel ssh.Channel
}

// ForwardRequestPayload defines the payload for slider-forward-request
type ForwardRequestPayload struct {
	Target  []int64
	ReqType string
	Payload []byte
}

type CustomTcpIpFwdRequest struct {
	Protocol  string
	IsSshConn bool
	*TcpIpFwdRequest
	// Forward destination fields (used by Slider console forwards, not SSH forwards)
	FwdHost string `json:"fwd_host,omitempty"`
	FwdPort uint32 `json:"fwd_port,omitempty"`
}

// TermDimensions is the custom structure of a message
// for window size info
type TermDimensions struct {
	Width  uint32
	Height uint32
	X      uint32
	Y      uint32
}

// CustomCmd is the custom structure of a message
// from a Session to execute a command
type CustomCmd struct {
	Path    string `json:"path"`
	Command string `json:"command"`
}
