package server

import (
	"errors"
	"fmt"
	"io"
	"slider/pkg/conf"
	"time"

	"github.com/spf13/pflag"
)

// ConnectCommand implements the 'connect' command
type ConnectCommand struct{}

func (c *ConnectCommand) Name() string        { return connectCmd }
func (c *ConnectCommand) Description() string { return connectDesc }
func (c *ConnectCommand) Usage() string       { return connectUsage }

func (c *ConnectCommand) Run(s *server, args []string, out io.Writer) error {
	connectFlags := pflag.NewFlagSet(connectCmd, pflag.ContinueOnError)
	connectFlags.SetOutput(out)

	cCert := connectFlags.Int64P("cert-id", "i", 0, "Specify certID for SSH key authentication")
	cDNS := connectFlags.StringP("dns", "d", "", "Use custom DNS resolver")
	cProto := connectFlags.StringP("proto", "p", conf.Proto, "Use custom proto")
	cTlsCert := connectFlags.StringP("tls-cert", "c", "", "Use custom client TLS certificate")
	cTlsKey := connectFlags.StringP("tls-key", "k", "", "Use custom client TLS key")

	connectFlags.Usage = func() {
		fmt.Fprintf(out, "Usage: %s\n\n", connectUsage)
		fmt.Fprintf(out, "%s\n\n", connectDesc)
		connectFlags.PrintDefaults()
	}

	if pErr := connectFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		s.console.PrintlnErrorStep("Flag error: %v", pErr)
		return nil
	}

	// Validate exact args
	if connectFlags.NArg() != 1 {
		s.console.PrintlnErrorStep("exactly 1 argument(s) required, got %d", connectFlags.NArg())
		return nil
	}

	clientURL := connectFlags.Args()[0]
	cu, uErr := conf.ResolveURL(clientURL)
	if uErr != nil {
		s.console.PrintlnErrorStep("Failed to resolve URL: %v", uErr)
		return nil
	}

	s.console.PrintlnDebugStep("Establishing Connection to %s (Timeout: %s)", cu.String(), conf.Timeout)

	notifier := make(chan bool, 1)
	timeout := time.Now().Add(conf.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)

	go s.newClientConnector(cu, notifier, *cCert, *cDNS, *cProto, *cTlsCert, *cTlsKey)

	for {
		select {
		case success := <-notifier:
			if success {
				s.console.PrintlnOkStep("Connection established")
				return nil
			}
			s.console.PrintlnErrorStep("Connection failed")
			return nil
		case <-ticker.C:
			if time.Now().Before(timeout) {
				fmt.Printf(".")
				continue
			} else {
				s.console.PrintlnErrorStep("Connection Timeout")
				return nil
			}
		}
	}
}
