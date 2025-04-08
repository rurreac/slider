package main

import (
	"flag"
	"slider/client"
)

func main() {
	flag.Parse()
	var flags = flag.Args()
	client.NewClient(flags)
}
