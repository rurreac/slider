package conf

import (
	"context"
	"fmt"
	"net"
	"strings"
)

func CustomResolver(cDNS string, host string) (string, error) {
	sdHost := strings.Split(cDNS, ":")

	switch len(sdHost) {
	case 1:
		cDNS = fmt.Sprintf("%s:53", sdHost[0])
	case 2:
		cDNS = net.JoinHostPort(sdHost[0], sdHost[1])
	default:
		return "", fmt.Errorf("invalid DNS host: %s", cDNS)
	}

	resolver := &net.Resolver{
		PreferGo:     true,
		StrictErrors: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := &net.Dialer{
				Timeout: dnsTimeout,
			}
			return dialer.DialContext(ctx, network, cDNS)
		},
	}
	rIP, rErr := resolver.LookupHost(context.Background(), host)
	if rErr != nil {
		return "", fmt.Errorf("failed to resolve host %s: %v", host, rErr)
	}

	// Use the first IP address returned by the resolver
	return rIP[0], nil
}
