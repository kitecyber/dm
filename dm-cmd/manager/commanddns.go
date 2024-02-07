package manager

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

type CommandDNS struct{}

func (cd *CommandDNS) SetDNS(iface, primaryDNS, secondaryDNS string) error {
	if !IsValidIP(primaryDNS) {
		return fmt.Errorf("invalid primary dns ip address %v", primaryDNS)
	}
	if !IsValidIP(secondaryDNS) {
		return fmt.Errorf("invalid secondary dns ip address %v", secondaryDNS)
	}
	var cmd *exec.Cmd
	if strings.ToLower(iface) == "all" {
		switch runtime.GOOS {
		case "windows":
			if !cd.HasCommand("netsh") {
				return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
			}
			interfaceNames, err := cd.GetActiveInterfaces()
			if interfaceNames == nil {
				return fmt.Errorf("unable to determine active interface")
			} else if err != nil {
				return err
			}
			for _, ifacename := range interfaceNames {
				cmd := exec.Command("netsh", "interface", "ip", "set", "dns", "name="+ifacename, "static", primaryDNS, secondaryDNS)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err = cmd.Run()
				if err != nil {
					return err
				}
			}

		case "linux":
			if !cd.HasCommand("nmcli") {
				return fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
			}

			interfaceNames, err := cd.GetActiveInterfaces()
			if interfaceNames == nil {
				return fmt.Errorf("unable to determine active interface")
			} else if err != nil {
				return err
			}

			for _, ifacename := range interfaceNames {
				cmd = exec.Command("nmcli", "connection", "modify", ifacename, "ipv4.dns", strings.Join([]string{primaryDNS, secondaryDNS}, ","))
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err = cmd.Run()
				if err != nil {
					return err
				}
			}

		case "darwin":
			if !cd.HasCommand("networksetup") {
				return fmt.Errorf("networksetup command not found, consider installing it")
			}
			interfaceNames, err := cd.GetActiveInterfaces()
			if interfaceNames == nil {
				return fmt.Errorf("unable to determine active interface")
			} else if err != nil {
				return err
			}
			for _, ifacename := range interfaceNames {
				cmd := exec.Command("networksetup", "-setdnsservers", ifacename, primaryDNS, secondaryDNS)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				err = cmd.Run()
				if err != nil {
					return err
				}
			}

		default:
			return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
		}
	} else if iface != "" {
		switch runtime.GOOS {
		case "windows":
			if !cd.HasCommand("netsh") {
				return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
			}
			cmd := exec.Command("netsh", "interface", "ip", "set", "dns", "name="+iface, "static", primaryDNS, secondaryDNS)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				return err
			}

		case "linux":
			if !cd.HasCommand("nmcli") {
				return fmt.Errorf("nmcli command not found, consider installing NetworkManager or use an alternative method for your Linux distribution")
			}
			cmd = exec.Command("nmcli", "connection", "modify", iface, "ipv4.dns", strings.Join([]string{primaryDNS, secondaryDNS}, ","))
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err != nil {
				return err
			}

		case "darwin":
			if !cd.HasCommand("networksetup") {
				return fmt.Errorf("networksetup command not found, consider installing it")
			}
			cmd := exec.Command("networksetup", "-setdnsservers", iface, primaryDNS, secondaryDNS)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
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

func (cd *CommandDNS) GetActiveInterfaces() ([]string, error) {
	ifaces := make([]string, 0)
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("Error getting network interfaces:" + err.Error())

	}

	for _, iface := range interfaces {
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
			ifaces = append(ifaces, iface.Name)
		}
	}

	return ifaces, nil
}

func (cd *CommandDNS) HasCommand(cmdName string) bool {
	_, err := exec.LookPath(cmdName)
	return err == nil
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

func (cd *CommandDNS) PostSetup() error {
	return nil
}

func (cd *CommandDNS) getDNSLinux() (string, string, error) {
	if !cd.HasCommand("nmcli") {
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
	if !cd.HasCommand("netsh") {
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
	if !cd.HasCommand("scutil") {
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
			dnsServer := strings.TrimSpace(strings.Split(line, ":")[1])

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
