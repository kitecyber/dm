package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "dm-cmd",
	Short: "dm-cmd is a platform agnostic device manager.",
	Long:  `dm-cmd is a platform agnostic device manager.It is a wrapper cli tool that works on top of windows, linux and darwin based machines.This tool supports basic DNS configurations and Firewall configurations.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Do Stuff Here

	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
