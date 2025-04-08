package main

import (
	"flag"
	"slider/server"
)

func main() {
	flag.Parse()
	var flags = flag.Args()
	server.NewServer(flags)
}
