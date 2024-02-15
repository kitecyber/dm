package cmd

import (
	"log"

	"github.com/kitecyber/dm/dm-cmd/manager"
	"github.com/kitecyber/dm/dm-cmd/manager/dns"
	"github.com/spf13/cobra"
)

var (
	scope        string
	primaryDNS   string
	secondaryDNS string
	iface        string
)

func init() {
	dnsCmd.Flags().StringVarP(&scope, "scope", "s", "system", "two types of the scopes. system|command.command is used to set through system based commands")
	dnsCmd.Flags().StringVarP(&primaryDNS, "pd", "", "", "provide primary dns")
	dnsCmd.Flags().StringVarP(&secondaryDNS, "sd", "", "", "provide secondary dns")
	dnsCmd.Flags().StringVarP(&iface, "interface", "i", "system", "provide interfaces based on the system")

	showCmd.Flags().StringVarP(&scope, "scope", "s", "system", "two types of the scopes. system|command")
	showCmd.Flags().StringVarP(&iface, "interface", "i", "system", "provide interfaces based on the system")
	unsetDns.Flags().StringVarP(&scope, "scope", "s", "system", "two types of the scopes. system|command")
	unsetDns.Flags().StringVarP(&iface, "interface", "i", "system", "provide interfaces based on the system")

	rootCmd.AddCommand(dnsCmd)
	dnsCmd.AddCommand(showCmd)
	dnsCmd.AddCommand(unsetDns)
}

var showCmd = &cobra.Command{
	Use:   "show",
	Short: "Displays dns information",
	Long:  "Displays current dns information based on interface or system level",
	Run: func(cmd *cobra.Command, args []string) {
		var idm manager.IDNSDeviceManager
		if scope == "system" {
			idm = new(dns.GlobalDNS)
			pd, sd, err := idm.GetDNS("system")
			println("Primary DNS:\t", pd, "\nSeconday DNS:\t", sd)
			if err != nil {
				log.Fatalln(err)
			}
		} else if scope == "command" {
			if iface == "" {
				log.Fatalln("interface cannot be empty")
			}
			idm = new(dns.CommandDNS)
			pd, sd, err := idm.GetDNS(iface)
			println("Primary DNS:", pd, "\nSeconday DNS:", sd)
			if err != nil {
				log.Fatalln(err)
			}
		} else {
			log.Fatalln("undefined scope.Scope can be system|command")
		}
	},
}
var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "dns sub-command is to configure dns",
	Long:  `dns sub-command is to configure dns, settings to be supplied.P`,
	Run: func(cmd *cobra.Command, args []string) {
		if primaryDNS == "" || secondaryDNS == "" {
			log.Fatalln("primary and secondary dns ips must be given")
		}

		var idm manager.IDNSDeviceManager
		if scope == "system" {
			idm = new(dns.GlobalDNS)
			err := idm.SetDNS("", primaryDNS, secondaryDNS)
			if err != nil {
				log.Fatalln(err)
			}
			println("Primary and secondary DNS servers set successfully.")
		} else if scope == "command" {
			if iface == "" {
				log.Fatalln("interface cannot be empty")
			}
			idm = new(dns.CommandDNS)

			err := idm.SetDNS(iface, primaryDNS, secondaryDNS)
			if err != nil {
				log.Fatalln(err)
			}
			println("Primary and secondary DNS servers set successfully.")
		} else {
			log.Fatalln("undefined scope.Scope can be system|command")
		}
	},
}
var unsetDns = &cobra.Command{
	Use:   "remove",
	Short: "Remove dns information",
	Long:  "Removes current dns information based on interface or system level",
	Run: func(cmd *cobra.Command, args []string) {
		var idm manager.IDNSDeviceManager
		if scope == "system" {
			idm = new(dns.GlobalDNS)
			err := idm.UnSetDNS("system")
			if err != nil {
				log.Fatalln(err)
			} else {
				println("DNS has been unset successfully")
			}
		} else if scope == "command" {
			if iface == "" {
				log.Fatalln("interface cannot be empty")
			}
			idm = new(dns.CommandDNS)
			err := idm.UnSetDNS(iface)
			if err != nil {
				log.Fatalln(err)
			} else {
				println("DNS has been unset successfully")
			}
		} else {
			log.Fatalln("undefined scope.Scope can be system|command")
		}
	},
}
