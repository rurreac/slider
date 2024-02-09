package main

import (
	"flag"
	"slider/client"
	"slider/server"
)

func main() {
	flag.Parse()
	var command string
	var flags = flag.Args()

	if len(flags) > 0 {
		command = flags[0]
		flags = flags[1:]
	}

	switch command {
	case "server":
		server.NewServer(flags)
	case "client":
		client.NewClient(flags)
	}
}
