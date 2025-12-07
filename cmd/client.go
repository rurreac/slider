package cmd

import (
	"slider/client"
)

func init() {
	rootCmd.AddCommand(client.NewCommand())
}
