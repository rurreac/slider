package server

import (
	"errors"
	"fmt"
	"slider/pkg/conf"
	"time"

	"github.com/spf13/pflag"
)

const (
	// Console Connect Command
	connectCmd   = "connect"
	connectDesc  = "Establishes a connection to a Client"
	connectUsage = "Usage: connect [flags] <client_address:port>"
)

// ConnectCommand implements the 'connect' command
type ConnectCommand struct{}

func (c *ConnectCommand) Name() string        { return connectCmd }
func (c *ConnectCommand) Description() string { return connectDesc }
func (c *ConnectCommand) Usage() string       { return connectUsage }

func (c *ConnectCommand) Run(ctx *ExecutionContext, args []string) error {
	server := ctx.Server()
	ui := ctx.UI()

	connectFlags := pflag.NewFlagSet(connectCmd, pflag.ContinueOnError)
	connectFlags.SetOutput(ui.Writer())

	cCert := connectFlags.Int64P("cert-id", "i", 0, "Specify certID for SSH key authentication")
	cDNS := connectFlags.StringP("dns", "d", "", "Use custom DNS resolver")
	cProto := connectFlags.StringP("proto", "p", conf.Proto, "Use custom proto")
	cTlsCert := connectFlags.StringP("tls-cert", "c", "", "Use custom client TLS certificate")
	cTlsKey := connectFlags.StringP("tls-key", "k", "", "Use custom client TLS key")

	connectFlags.Usage = func() {
		_, _ = fmt.Fprintf(ui.Writer(), "Usage: %s\n\n", connectUsage)
		_, _ = fmt.Fprintf(ui.Writer(), "%s\n\n", connectDesc)
		connectFlags.PrintDefaults()
	}

	if pErr := connectFlags.Parse(args); pErr != nil {
		if errors.Is(pErr, pflag.ErrHelp) {
			return nil
		}
		ui.PrintError("Flag error: %v", pErr)
		return nil
	}

	// Validate exact args
	if connectFlags.NArg() != 1 {
		ui.PrintError("exactly 1 argument(s) required, got %d", connectFlags.NArg())
		return nil
	}

	clientURL := connectFlags.Args()[0]
	cu, uErr := conf.ResolveURL(clientURL)
	if uErr != nil {
		ui.PrintError("Failed to resolve URL: %v", uErr)
		return nil
	}

	ui.PrintInfo("Establishing Connection to %s (Timeout: %s)", cu.String(), conf.Timeout)

	notifier := make(chan bool, 1)
	timeout := time.Now().Add(conf.Timeout)
	ticker := time.NewTicker(500 * time.Millisecond)

	go server.newClientConnector(cu, notifier, *cCert, *cDNS, *cProto, *cTlsCert, *cTlsKey)

	for {
		select {
		case success := <-notifier:
			if success {
				ui.PrintSuccess("Connection established")
				return nil
			}
			ui.PrintError("Connection failed")
			return nil
		case <-ticker.C:
			if time.Now().Before(timeout) {
				fmt.Printf(".")
				continue
			} else {
				ui.PrintError("Connection Timeout")
				return nil
			}
		}
	}
}
