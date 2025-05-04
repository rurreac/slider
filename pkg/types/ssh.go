package types

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

type CustomTcpIpChannelMsg struct {
	IsSshConn bool
	*TcpIpChannelMsg
}

type CustomTcpIpFwdRequest struct {
	IsSshConn bool
	*TcpIpFwdRequest
}

// TermDimensions is the custom structure of a message
// for window size info
type TermDimensions struct {
	Width  uint32
	Height uint32
	X      uint32
	Y      uint32
}
