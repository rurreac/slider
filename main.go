package main

import (
	"flag"
	"fmt"
	"slider/client"
	"slider/server"
)

const help = `
Slider is a program able to run as: 

* Server with the basic functionality of a Command & Control (C2) 
* Client acting as an Agent that connects back to the Server counterpart.

  Source Code available at: 
	https://github.com/rurreac/slider

Usage:
  slider [command]

Available Commands:
  client	Runs a Slider Client instance
  server	Runs a Slider Server instance
  help		Print this information out`

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
	default:
		fmt.Printf("%s\n\n", help)
	}
}
