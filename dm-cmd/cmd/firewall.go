package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/kitecyber/dm/dm-cmd/manager"
	"github.com/kitecyber/dm/dm-cmd/manager/firewall"
	"github.com/spf13/cobra"
)

var (
	ruleName  string
	direction string
	action    string
	protocol  string
	remoteip  string
	port      string
)

func init() {
	firewallCmd.Flags().StringVarP(&ruleName, "rulename", "n", "", "a firewall rule name to be given")
	firewallCmd.Flags().StringVarP(&direction, "direction", "d", "in", "direction is inbound or outbound. in|out to be given.")
	firewallCmd.Flags().StringVarP(&action, "action", "a", "block", "action is allow|block.Default value is block") // unix based sytems accept deny rather than block.This tool uses block.
	firewallCmd.Flags().StringVarP(&protocol, "protocol", "p", "any", "a protocol name to be given.The following are the list of the supported protocols tcp|ssh|ftp|sftp|scp|udp|dns|dhcp|imap|smtp|pop|snpm|sip|rtp|rtcp.Default is [any] which means all protocols")
	firewallCmd.Flags().StringVarP(&remoteip, "remoteip", "i", "any", "remoteip is a valid ipv4 ip address or valid cidr notation.Default is [any] which means all ip addresses")
	firewallCmd.Flags().StringVarP(&port, "port", "r", "any", "port is a value between 0-65535.Default is [any] which means all ports")

	showFirewallCmd.Flags().StringVarP(&ruleName, "rulename", "n", "", "a firewall rule name to be given")

	rootCmd.AddCommand(firewallCmd)
	firewallCmd.AddCommand(showFirewallCmd)
}

var showFirewallCmd = &cobra.Command{
	Use:   "show",
	Short: "Displays firewall information",
	Long:  "Displays current firewall information based on other inputs",
	Run: func(cmd *cobra.Command, args []string) {
		var ifw manager.IFirewallManager
		fw := new(firewall.Firewall)
		ifw = fw
		output, err := ifw.ShowFirewall(ruleName)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Println(output)
	},
}
var firewallCmd = &cobra.Command{
	Use:   "firewall",
	Short: "firewall is to configure firewall rule",
	Long:  `firewall is to configure firewall rule.Required values protocol,port,remote-ip, direction, action values to be supplied`,
	Run: func(cmd *cobra.Command, args []string) {
		var ifw manager.IFirewallManager
		fw := new(firewall.Firewall)
		ifw = fw
		if ruleName == "" {
			ruleName = getSHA(direction + action + protocol + remoteip + port)
		}
		err := ifw.SetFirewall(ruleName, direction, action, protocol, remoteip, port)
		if err != nil {
			log.Fatalln(err)
		}
		println("Firewall rule successfully created.Here is the Rule Name:", ruleName)
	},
}

func getSHA(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	hashedBytes := hasher.Sum(nil)
	hashedString := hex.EncodeToString(hashedBytes)
	return hashedString
}
