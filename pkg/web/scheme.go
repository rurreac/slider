package web

import (
	"fmt"
	"net"
	"net/url"
)

func ResolveURL(rawURL string) (*url.URL, error) {
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
	host, port, hErr := net.SplitHostPort(u.Host)
	if hErr != nil {
		return nil, fmt.Errorf("not a valid host: %v", hErr)
	}
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	if host == "" {
		host = "localhost"
	}
	u.Host = net.JoinHostPort(host, port)

	return u, nil
}
