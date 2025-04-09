package conf

import (
	"crypto/tls"
	"fmt"
	"github.com/gorilla/websocket"
	"net/url"
	"strings"
)

var DefaultWebSocketDialer = &websocket.Dialer{
	NetDial:          nil,
	HandshakeTimeout: Timeout,
	Subprotocols:     nil,
	// Use Default Buffer Size
	ReadBufferSize:  0,
	WriteBufferSize: 0,
	TLSClientConfig: &tls.Config{},
}

var DefaultWebSocketUpgrader = &websocket.Upgrader{
	HandshakeTimeout: Timeout,
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
