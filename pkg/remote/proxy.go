package remote

import (
	"encoding/json"
	"fmt"
	"slider/pkg/conf"
	"slider/pkg/session"
	"slider/pkg/slog"
	"slider/pkg/types"

	"golang.org/x/crypto/ssh"
)

// Proxy represents a remote connection proxy for gateway mode
type Proxy struct {
	gateway    session.Session
	targetPath []int64
}

// NewProxy creates a new remote connection proxy
func NewProxy(gateway session.Session, path []int64) *Proxy {

	return &Proxy{
		gateway:    gateway,
		targetPath: path,
	}
}

// OpenChannel proxies an OpenChannel request via slider-connect
func (p *Proxy) OpenChannel(name string, payload []byte) (ssh.Channel, <-chan *ssh.Request, error) {
	req := ConnectRequest{
		Target:      p.targetPath,
		ChannelType: name,
		Payload:     payload,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal connect request: %w", err)
	}

	p.gateway.GetLogger().DebugWith("Remote OpenChannel Proxying",
		slog.F("channel", name),
		slog.F("target", p.targetPath),
	)

	return p.gateway.GetSSHClient().OpenChannel(conf.SSHChannelSliderConnect, data)
}

// SendRequest proxies a global request via slider-forward-request
func (p *Proxy) SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error) {
	req := types.ForwardRequestPayload{
		Target:  p.targetPath,
		ReqType: name,
		Payload: payload,
	}
	data, err := json.Marshal(req)
	if err != nil {
		return false, nil, fmt.Errorf("failed to marshal forward request: %w", err)
	}

	p.gateway.GetLogger().DebugWith("Remote SendRequest Proxying",
		slog.F("request", name),
		slog.F("target", p.targetPath),
	)

	return p.gateway.GetSSHClient().SendRequest(conf.SSHRequestSliderForward, wantReply, data)
}

// ParsePath parses a target path from []int64
// Returns the next hop ID and the remaining path
func (p *Proxy) ParsePath() (nextHop int, remaining []int64, err error) {
	if len(p.targetPath) == 0 {
		return 0, nil, nil
	}

	nextHop = int(p.targetPath[0])
	if len(p.targetPath) > 1 {
		remaining = p.targetPath[1:]
	}

	return nextHop, remaining, nil
}

// ConnectRequest defines the payload for slider-connect channel
type ConnectRequest struct {
	Target      []int64 `json:"target"`       // Target path (e.g., [1, 2, 3])
	ChannelType string  `json:"channel_type"` // e.g., "sftp"
	Payload     []byte  `json:"payload"`      // Optional payload for the channel
}

// Wait waits for the underlying connection to close (delegates to gateway)
func (p *Proxy) Wait() error {
	return p.gateway.GetSSHConn().Wait()
}
