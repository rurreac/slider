package listener

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"slider/pkg/conf"
	"strings"

	"github.com/gorilla/websocket"
)

var DefaultWebSocketDialer = &websocket.Dialer{
	NetDial:          nil,
	HandshakeTimeout: conf.Timeout,
	Subprotocols:     nil,
	// Use Default Buffer Size
	ReadBufferSize:    0,
	WriteBufferSize:   0,
	EnableCompression: true,
	TLSClientConfig:   &tls.Config{},
}

var DefaultWebSocketUpgrader = &websocket.Upgrader{
	HandshakeTimeout: conf.Timeout,
}

func FormatToWS(u *url.URL) (*url.URL, error) {
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "":
		u.Scheme = "ws"
	default:
		return u, fmt.Errorf("unknown client url scheme \"%s\"", u.Scheme)
	}
	return u, nil
}

func ResolveURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, fmt.Errorf("empty URL")
	}
	// url.Parse will return an error if there is no scheme, but we want to assume that's HTTP
	miniParse := strings.Split(rawURL, "://")
	if len(miniParse) == 1 {
		rawURL = fmt.Sprintf("http://%s", rawURL)
	}
	u, pErr := url.Parse(rawURL)
	if pErr != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", pErr)
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" {
		return nil, fmt.Errorf("host must be specified")
	}

	return u, nil
}

// WebSocket operation constants
const (
	OperationClient      = "client"
	OperationServer      = "server"
	OperationPromiscuous = "promiscuous"
)

// IsSliderWebSocket checks if the request is a slider WebSocket upgrade
// accepting any of the provided operations
func IsSliderWebSocket(r *http.Request, customProto string, operations []string) bool {
	upgradeHeader := r.Header.Get("Upgrade")
	if strings.ToLower(upgradeHeader) != "websocket" {
		return false
	}

	proto := HttpVersionResponse.ProtoVersion
	if customProto != "" && customProto != HttpVersionResponse.ProtoVersion {
		proto = customProto
	}

	secProto := r.Header.Get("Sec-WebSocket-Protocol")
	secOperation := r.Header.Get("Sec-WebSocket-Operation")

	if secProto != proto {
		return false
	}

	for _, op := range operations {
		if secOperation == op {
			return true
		}
	}
	return false
}
