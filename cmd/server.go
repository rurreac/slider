package cmd

import (
	"slider/server"
)

func init() {
	rootCmd.AddCommand(server.NewCommand())
}
