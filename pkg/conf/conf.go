package conf

import (
	"time"
)

// Timeout acts as the general Timeout defValue
var Timeout = 10 * time.Second

var dnsTimeout = 5 * time.Second

// Keepalive acts as the general KeepAlive defValue
var Keepalive = 60 * time.Second

// MinKeepAlive is the minimum keepalive allowed duration
var MinKeepAlive = 5 * time.Second
