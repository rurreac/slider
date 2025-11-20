package cmd

import (
	"os"

	"slider/pkg/conf"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "slider",
	Short: "Slider - A Command & Control (C2) application",
	Long: `Slider is a program able to run as:

* Server with the basic functionality of a Command & Control (C2) application.
* Client acting as an Agent that connects back to the Server counterpart, or listens for connections.

  Source Code available at:
	https://github.com/rurreac/slider`,
	SilenceUsage: true,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Shows Binary Build info",
	Run: func(cmd *cobra.Command, args []string) {
		conf.PrintVersion()
	},
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		// Error is already printed by the command, just exit
		os.Exit(1)
	}
}
