package conf

import (
	"flag"
	"time"
)

// Timeout acts as the general Timeout value
var Timeout = 10 * time.Second

var dnsTimeout = 5 * time.Second

// Keepalive acts as the general KeepAlive value
var Keepalive = 60 * time.Second

// MinKeepAlive is the minimum keepalive allowed duration
var MinKeepAlive = 5 * time.Second

func FlagIsDefined(flagSet *flag.FlagSet, flagName string) bool {
	var flagIsUsed bool
	flagSet.Visit(func(f *flag.Flag) {
		if f.Name == flagName {
			flagIsUsed = true
		}
	})
	return flagIsUsed
}
