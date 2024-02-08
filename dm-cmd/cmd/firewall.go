package cmd

import (
	"github.com/spf13/cobra"
)

func init() {

	rootCmd.AddCommand(firewallCmd)
	firewallCmd.AddCommand(showFirewallCmd)
}

var showFirewallCmd = &cobra.Command{
	Use:   "show",
	Short: "Displays firewall information",
	Long:  "Displays current firewall information based on other inputs",
	Run: func(cmd *cobra.Command, args []string) {

	},
}
var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "firewall is to configure firewall",
	Long:  `firewall is to configure firewall, settings to be supplied`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
