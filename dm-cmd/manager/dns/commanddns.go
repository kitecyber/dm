//go:build linux || darwin
// +build linux darwin

package dns

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strings"
	"syscall"

	"github.com/kitecyber/dm/dm-cmd/manager"
)

type CommandDNS struct{}

func (cd *CommandDNS) SetDNS(iface, primaryDNS, secondaryDNS string) error {
	if !manager.IsValidIP(primaryDNS) {
		return fmt.Errorf("invalid primary dns ip address %v", primaryDNS)
	}
	if !manager.IsValidIP(secondaryDNS) {
		return fmt.Errorf("invalid secondary dns ip address %v", secondaryDNS)
	}
	var cmd *exec.Cmd
	if strings.ToLower(iface) == "all" {
		switch runtime.GOOS {
		case "windows":
			if !manager.HasCommand("netsh") {
				return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
			}
			hasOneSet := false
			for _, activeIface := range manager.ActiveInterfaces {
				cmdPrimary := exec.Command("netsh", "interface", "ipv4", "set", "dns", "name="+activeIface, "source=static", "addr="+primaryDNS)
				cmdSecondary := exec.Command("netsh", "interface", "ipv4", "add", "dns", "name="+activeIface, "addr="+secondaryDNS, "index=2")
				err1 := cmdPrimary.Run()
				if err1 != nil {
					log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", activeIface, err1.Error())
				}
				err2 := cmdSecondary.Run()
				if err2 != nil {
					log.Printf("Error setting Secondary DNS for the interface:%v.Error:%v", activeIface, err2.Error())
				}
				if err1 == nil && err2 == nil {
					hasOneSet = true
				}
			}
			if !hasOneSet {
				return fmt.Errorf("error setting DNS servers")
			}

		case "linux":
			if !manager.HasCommand("nmcli") {
				return fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
			}
			hasOneSet := false
			for _, activeIface := range manager.ActiveInterfaces {
				connName, err := getConnectionNameforLinux(activeIface)
				if err != nil {
					log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", activeIface, err.Error())
				}
				if err == nil {
					hasOneSet = true
				}
				cmd = exec.Command("nmcli", "connection", "modify", connName, "ipv4.dns", strings.Join([]string{primaryDNS, secondaryDNS}, ","))

				cmd.SysProcAttr = &syscall.SysProcAttr{}
				cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
				err = cmd.Run()
				if err != nil {
					log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", activeIface, err.Error())
				}
				if err == nil {
					hasOneSet = true
				}
			}
			if !hasOneSet {
				return fmt.Errorf("error setting DNS servers")
			}
			//	cmd = exec.Command("nmcli", "connection", "modify", ifacename, "ipv4.dns", strings.Join([]string{primaryDNS, secondaryDNS}, ","))

		case "darwin":
			if !manager.HasCommand("networksetup") {
				return fmt.Errorf("networksetup command not found, consider installing it")
			}
			hasOneSet := false
			for _, activeIface := range manager.ActiveInterfaces {
				cmd := exec.Command("networksetup", "-setdnsservers", activeIface, primaryDNS, secondaryDNS)
				cmd.SysProcAttr = &syscall.SysProcAttr{}
				cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
				err := cmd.Run()
				if err != nil {
					log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", activeIface, err.Error())
				}
				if err == nil {
					hasOneSet = true
				}
			}
			if !hasOneSet {
				return fmt.Errorf("error setting DNS servers")
			}

		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	} else if iface != "" {
		switch runtime.GOOS {
		case "windows":
			if !manager.HasCommand("netsh") {
				return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
			}
			cmdPrimary := exec.Command("netsh", "interface", "ipv4", "set", "dns", "name="+iface, "source=static", "addr="+primaryDNS)
			cmdSecondary := exec.Command("netsh", "interface", "ipv4", "add", "dns", "name="+iface, "addr="+secondaryDNS, "index=2")

			cmdPrimary.SysProcAttr = &syscall.SysProcAttr{}
			cmdPrimary.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			err1 := cmdPrimary.Run()
			if err1 != nil {
				return fmt.Errorf("error setting Primary DNS for the interface:%v.Error:%v", iface, err1.Error())
			}
			cmdSecondary.SysProcAttr = &syscall.SysProcAttr{}
			cmdSecondary.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			err2 := cmdSecondary.Run()
			if err2 != nil {
				return fmt.Errorf("error setting Secondary DNS for the interface:%v.Error:%v", iface, err2.Error())
			}
		case "linux":
			if !manager.HasCommand("nmcli") {
				return fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
			}
			connName, err := getConnectionNameforLinux(iface)
			if err != nil {
				return err
			}
			cmd = exec.Command("nmcli", "connection", "modify", connName, "ipv4.dns", strings.Join([]string{primaryDNS, secondaryDNS}, ","))
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			err = cmd.Run()
			if err != nil {
				return err
			}

		case "darwin":
			if !manager.HasCommand("networksetup") {
				return fmt.Errorf("networksetup command not found, consider installing it")
			}
			cmd := exec.Command("networksetup", "-setdnsservers", iface, primaryDNS, secondaryDNS)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			err := cmd.Run()
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	}
	return nil
}

func (cd *CommandDNS) GetDNS(iface string) (string, string, error) {
	switch runtime.GOOS {
	case "windows":
		return cd.getDNSWindows()
	case "linux":
		return cd.getDNSLinux()
	case "darwin":
		return cd.getDNSDarwin()
	default:
		return "", "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func (cd *CommandDNS) UnSetDNS(iface string) error {
	var cmd *exec.Cmd
	if strings.ToLower(iface) == "all" {
		switch runtime.GOOS {
		case "windows":
			if !manager.HasCommand("netsh") {
				return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
			}
			for _, iface := range manager.ActiveInterfaces {
				cmdPrimary := exec.Command("netsh", "interface", "ipv4", "delete", "dns", iface, "all")
				err := cmdPrimary.Run()
				if err != nil {
					log.Printf("Error un-setting Primary DNS for the interface:%v.Error:%v", iface, err.Error())
					return err
				}
			}

		case "linux":
			if !manager.HasCommand("nmcli") {
				return fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
			}
			for _, activeIface := range manager.ActiveInterfaces {
				connName, err := getConnectionNameforLinux(activeIface)
				if err != nil {
					return err
				}
				cmd = exec.Command("nmcli", "connection", "modify", connName, "ipv4.dns", "")
				cmd.SysProcAttr = &syscall.SysProcAttr{}
				cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
				err = cmd.Run()
				if err != nil {
					log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", activeIface, err.Error())
					return err
				}
			}

		case "darwin":
			if !manager.HasCommand("networksetup") {
				return fmt.Errorf("networksetup command not found, consider installing it")
			}
			for _, activeIface := range manager.ActiveInterfaces {

				// Remove primary DNS
				removePrimaryDNSCmd := exec.Command("networksetup", "-setdnsservers", activeIface, "empty")

				// Remove secondary DNS
				removeSecondaryDNSCmd := exec.Command("networksetup", "-setdnsservers", activeIface, "empty")

				// Run commands
				removePrimaryDNSCmd.SysProcAttr = &syscall.SysProcAttr{}
				removePrimaryDNSCmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
				if err := removePrimaryDNSCmd.Run(); err != nil {
					log.Printf("Error un-setting Secondary DNS for the interface:%v.Error:%v", activeIface, err.Error())
					return err
				}

				removeSecondaryDNSCmd.SysProcAttr = &syscall.SysProcAttr{}
				removeSecondaryDNSCmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
				if err := removeSecondaryDNSCmd.Run(); err != nil {
					log.Printf("Error un-setting Secondary DNS for the interface:%v.Error:%v", activeIface, err.Error())
					return err
				}
			}

		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	} else if iface != "" {
		switch runtime.GOOS {
		case "windows":
			if !manager.HasCommand("netsh") {
				return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
			}
			cmdPrimary := exec.Command("netsh", "interface", "ipv4", "delete", "dns", iface, "all")
			err := cmdPrimary.Run()
			if err != nil {
				log.Printf("Error un-setting Primary DNS for the interface:%v.Error:%v", iface, err.Error())
				return err
			}

		case "linux":
			if !manager.HasCommand("nmcli") {
				return fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
			}
			fmt.Println(iface)
			connName, err := getConnectionNameforLinux(iface)
			fmt.Println("connName", connName)
			if err != nil {
				return err
			}
			cmd = exec.Command("nmcli", "connection", "modify", connName, "ipv4.dns", "")
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			err = cmd.Run()
			if err != nil {
				log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", iface, err.Error())
				return err
			}

		case "darwin":
			if !manager.HasCommand("networksetup") {
				return fmt.Errorf("networksetup command not found, consider installing it")
			}
			// Remove primary DNS
			removePrimaryDNSCmd := exec.Command("networksetup", "-setdnsservers", iface, "empty")

			// Remove secondary DNS
			removeSecondaryDNSCmd := exec.Command("networksetup", "-setdnsservers", iface, "empty")

			// Run commands
			removePrimaryDNSCmd.SysProcAttr = &syscall.SysProcAttr{}
			removePrimaryDNSCmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			if err := removePrimaryDNSCmd.Run(); err != nil {
				log.Printf("Error un-setting Secondary DNS for the interface:%v.Error:%v", iface, err.Error())
				return err
			}

			removeSecondaryDNSCmd.SysProcAttr = &syscall.SysProcAttr{}
			removeSecondaryDNSCmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
			if err := removeSecondaryDNSCmd.Run(); err != nil {
				log.Printf("Error un-setting Secondary DNS for the interface:%v.Error:%v", iface, err.Error())
				return err
			}

		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	}
	return nil
}

func (cd *CommandDNS) PostSetup() error {
	return nil
}

func (cd *CommandDNS) getDNSLinux() (string, string, error) {
	if !manager.HasCommand("nmcli") {
		return "", "", fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
	}
	// Execute the nmcli command to get DNS information
	cmd := exec.Command("nmcli", "dev", "show")
	output, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("error running nmcli: %v", err)
	}

	// Parse the output to extract DNS information
	var primaryDNS, secondaryDNS string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "IP4.DNS[1]:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				primaryDNS = fields[1]
			}
		} else if strings.Contains(line, "IP4.DNS[2]:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				secondaryDNS = fields[1]
			}
		}
	}

	return primaryDNS, secondaryDNS, nil
}

func (cd *CommandDNS) getDNSWindows() (string, string, error) {
	if !manager.HasCommand("netsh") {
		return "", "", fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
	}
	cmd := exec.Command("netsh", "interface", "ip", "show", "dns")
	output, err := cmd.Output()
	if err != nil {
		return "", "", err
	}

	// Convert output bytes to string
	outputStr := string(output)

	// Find lines containing DNS server information
	lines := strings.Split(outputStr, "\n")
	var primaryDNS, secondaryDNS string
	for _, line := range lines {
		if strings.Contains(line, "Configuration for interface") {
			// Extract primary and secondary DNS from the next lines
			for i := 0; i < 2; i++ {
				line = lines[i]
				if strings.Contains(line, "DNS servers configured through DHCP") {
					// DHCP is used, no manual DNS configuration
					primaryDNS = "Obtained from DHCP"
					secondaryDNS = "Obtained from DHCP"
					break
				} else if strings.Contains(line, "Statically Configured DNS Servers") {
					// Static DNS configuration found
					dnsServers := strings.Fields(line)
					if len(dnsServers) >= 6 {
						primaryDNS = dnsServers[4]
					}
					if len(dnsServers) >= 8 {
						secondaryDNS = dnsServers[6]
					}
					break
				}
			}
			break
		}
	}
	return primaryDNS, secondaryDNS, nil
}

func (cd *CommandDNS) getDNSDarwin() (string, string, error) {
	if !manager.HasCommand("scutil") {
		return "", "", fmt.Errorf("scutil command not found for operating system: %s", runtime.GOOS)
	}
	cmd := exec.Command("scutil", "--dns")
	output, err := cmd.Output()
	if err != nil {

		return "", "", err
	}

	// Convert output bytes to string
	outputStr := string(output)

	// Split output by newline
	lines := strings.Split(outputStr, "\n")

	// Initialize variables to store primary and secondary DNS servers
	var primaryDNS, secondaryDNS string

	// Iterate through lines to find DNS servers
	for _, line := range lines {
		// Look for "nameserver" entries
		if strings.Contains(line, "nameserver[") {
			// Extract DNS server IP address
			dnsServer := strings.TrimSpace(strings.SplitN(line, ":", 1)[0])

			// If primaryDNS is empty, assign the first DNS server to it
			if primaryDNS == "" {
				primaryDNS = dnsServer
			} else {
				// If secondaryDNS is empty, assign the second DNS server to it
				secondaryDNS = dnsServer
				break
			}
		}
	}

	return primaryDNS, secondaryDNS, nil
}

func getConnectionNameforLinux(interfaceName string) (string, error) {
	// Run nmcli to get the connection name associated with the interface
	cmd := exec.Command("nmcli", "device", "show", interfaceName)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}

	// Parse the output to find the connection name
	lines := strings.Split(out.String(), "\n")
	for _, line := range lines {
		if strings.Contains(line, "GENERAL.CONNECTION") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				return strings.TrimSpace(parts[1]), nil
			}
		}
	}

	// Connection name not found
	return "", fmt.Errorf("connection name not found for interface %s", interfaceName)
}

func (cd *CommandDNS) GetDeviceName() (string, error) {
	switch runtime.GOOS {
	case "darwin":
		return "macOS", nil
	case "linux":
		// Execute the command
		cmd := exec.Command("nmcli", "dev", "show")
		var out bytes.Buffer
		cmd.Stdout = &out

		err := cmd.Run()
		if err != nil {
			return "", fmt.Errorf("failed to execute nmcli command: %v", err)
		}

		// Read the output line by line
		scanner := bufio.NewScanner(&out)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "GENERAL.DEVICE:") {
				// Extract the device name
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					fmt.Println(fields[1])
					return fields[1], nil
				}
			}
		}

		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("error reading command output: %v", err)
		}
		return "", fmt.Errorf("GENERAL.DEVICE not found in nmcli output")
	case "windows":
		return "Windows", nil
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}
