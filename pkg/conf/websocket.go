package conf

import (
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
}

var DefaultWebSocketUpgrader = &websocket.Upgrader{
	HandshakeTimeout: Timeout,
}

func FormatToWS(u *url.URL) (string, error) {
	var wsURL string
	switch u.Scheme {
	case "http":
		wsURL = fmt.Sprintf("ws://%s", strings.TrimPrefix(u.String(), u.Scheme+"://"))
	case "https":
		wsURL = fmt.Sprintf("wss://%s", strings.TrimPrefix(u.String(), u.Scheme+"://"))
	case "":
		wsURL = fmt.Sprintf("ws://%s", u.String())
	default:
		return "", fmt.Errorf("unknown client url scheme \"%s\"", u.Scheme)
	}
	return wsURL, nil
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
