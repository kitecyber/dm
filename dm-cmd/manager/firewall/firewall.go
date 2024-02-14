package firewall

import (
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/kitecyber/dm/dm-cmd/manager"
)

var Protocols []string

type Firewall struct{}

func init() {
	Protocols = []string{"ANY", "ALL", "SSH", "FTP", "SFTP", "SCP", "UDP", "DNS", "DHCP", "IMAP", "SMTP", "POP", "SNPM", "SIP", "RTP", "RTCP", "TCP"}
}

func (f *Firewall) SetFirewall(rulename, direction, action, protocol, remoteip, port string) error {
	err := validateFirewallInput(rulename, direction, action, protocol, remoteip, port)
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		protocol = strings.ToLower(protocol)
		if protocol == "" {
			protocol = "any"
		}

		if ok, err := firewallRuleExistsWindows(rulename); ok {
			return fmt.Errorf("firewall already exists with the given rule:%v", rulename)
		} else {
			if err != nil {
				return err
			}
		}
		var cmdFirewall *exec.Cmd
		// post can be set only if the protocol is tcp or udp
		if (strings.ToLower(protocol) == "tcp" || strings.ToLower(protocol) == "udp") && port != "" {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+rulename, "dir="+direction, "action="+action, "protocol="+protocol, "remoteip="+remoteip, "localport="+port)
		} else {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+rulename, "dir="+direction, "action="+action, "protocol="+protocol, "remoteip="+remoteip)
		}

		err := cmdFirewall.Run()
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}
	case "linux":
		if strings.ToLower(action) == "block" {
			action = "deny"
		}
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)

	case "darwin":
		if strings.ToLower(action) == "allow" {
			action = "pass"
		}

		if ok, err := firewallAnchorExistsDarwin(rulename); ok {
			return fmt.Errorf("firewall already exists with the given rule:%v", rulename)
		} else {
			if err != nil {
				return err
			}
		}

		// There is no rule name concept in darwin based systems.
		// anchors are used to group a rule or rules.
		line := fmt.Sprintln("anchor", rulename, "{")
		// line = line + fmt.Sprintln(action, " ", direction, " ", "proto", " ", protocol, " ", "from", " ", "any", " ", "to", " ", remoteip, " ", "port", " ", port)
		line = line + fmt.Sprintln("\t", action, direction, "proto", protocol, "from", "any", "to", remoteip, "port", port)
		line = line + "}"

		cmd := exec.Command("sh", "-c", fmt.Sprintf("echo '%s' >> /etc/pf.conf", line))
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}

	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)

	}
	return nil
}

func (f *Firewall) ShowFirewall(rulename string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return "", fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		if rulename == "" {
			rulename = "all"
		}
		var cmdFirewall *exec.Cmd
		cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+rulename)
		output, err := cmdFirewall.Output()
		if err != nil {
			return "", fmt.Errorf("error while showing firewall rule.Error:%v", err.Error())
		}
		return string(output), nil
	case "linux":
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	case "darwin":
		var cmd *exec.Cmd
		if rulename == "all" || rulename == "any" {
			cmd = exec.Command("pfctl", "-sr")
		} else {
			cmd = exec.Command("pfctl", "-a", rulename, "-s", "rules")
		}
		output, err := cmd.CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("error fetching firewall rules:%v", err.Error())
		}
		return string(output), nil

	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func (f *Firewall) GetFirewall(rulename string) (firewall map[string]string, err error) {
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return nil, fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		if strings.ToLower(rulename) == "all" || strings.ToLower(rulename) == "any" {
			return nil, fmt.Errorf("invalid rule name")
		}
		var cmdFirewall *exec.Cmd
		cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+rulename)
		output, err := cmdFirewall.Output()
		if err != nil {
			return nil, fmt.Errorf("error while showing firewall rule.Error:%v", err.Error())
		}
		return f.ToMap(string(output))
	case "linux":
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	case "darwin":
		var cmd *exec.Cmd
		cmd = exec.Command("pfctl", "-a", rulename, "-s", "rules")
		output, err := cmd.CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("error fetching firewall rules:%v", err.Error())
		}
		return f.ToMap(string(output))

	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

// any commands to run after setup.Like restart the servers etc..
func (f *Firewall) PostSetup() error {
	switch runtime.GOOS {
	case "windows":

	case "linux":

	case "darwin":
		if !manager.HasCommand("pfctl") {
			return fmt.Errorf("pfctl command not found for operating system: %s", runtime.GOOS)
		}
		cmd := exec.Command("pfctl", "-f", "/etc/pf.conf")
		err := cmd.Run()
		if err != nil {
			return err
		}
		println("configuration successfully reloaded")
		return nil

	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil
}

func (f *Firewall) ToMap(output string) (map[string]string, error) {
	outputMap := make(map[string]string, 0)
	switch runtime.GOOS {
	case "windows":
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lineSep := strings.Split(line, ":")
			if len(lineSep) == 2 {
				switch lineSep[0] {
				case "Direction":
					outputMap["direction"] = lineSep[1]
				case "Action":
					outputMap["action"] = strings.ToLower(lineSep[1])
				case "Protocol":
					outputMap["protocol"] = strings.ToLower(lineSep[1])
				case "RemoteIP":
					outputMap["remoteIP"] = lineSep[1]
				case "RemotePort":
					outputMap["port"] = lineSep[1]
				}
			}
		}
		if len(outputMap) > 0 {
			return outputMap, nil
		}
		return outputMap, fmt.Errorf("no data found")

	case "linux":
		return nil, fmt.Errorf("not implemented")

	case "darwin":
		strs := strings.Split(output, " ")
		for i, str := range strs {

			switch str {
			case "pass", "block":
				outputMap["action"] = str
			case "in", "out":
				outputMap["direction"] = str
			case "proto":
				if len(strs) >= i+1 {
					outputMap["protocol"] = strs[i+1]
				}
			case "port":
				if len(strs) >= i+1 {
					outputMap["port"] = strs[i+1]
				}
			case "to":
				if len(strs) >= i+1 {
					outputMap["remoteIP"] = strs[i+1]
				}
			}
			if len(outputMap) > 0 {
				return outputMap, nil
			}
			return outputMap, fmt.Errorf("no data found")
		}

	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil, nil
}

func validateFirewallInput(rulename, direction, action, protocol, remoteip, port string) error {
	if rulename == "" {
		return fmt.Errorf("invalid rule name.Rule name must not be empty")
	}
	if !(strings.ToLower(direction) == "in" || strings.ToLower(direction) == "out") {
		return fmt.Errorf("invalid direction.Direction must be in|out")
	}
	if !(strings.ToLower(action) == "allow" || strings.ToLower(direction) == "block") {
		return fmt.Errorf("invalid action.Action must be allow|block")
	}
	hasFound := false
	for _, p := range Protocols {
		if strings.EqualFold(p, protocol) {
			hasFound = true
			break
		}
	}
	if !hasFound {
		return fmt.Errorf("invalid protocol")
	}
	if !(remoteip == "" || strings.ToLower(remoteip) == "all" || strings.ToLower(remoteip) == "any") {
		if !manager.IsValidIPAddressOrCIDR(remoteip) {
			return fmt.Errorf("invalid ip address or cidr notation")
		}
	}

	if port != "any" {
		if !manager.IsValidPort(port) {
			return fmt.Errorf("invalid port")
		}
	}
	return nil
}

func firewallRuleExistsWindows(ruleName string) (bool, error) {
	// Run PowerShell command to check if the firewall rule exists
	if !manager.HasCommand("netsh") {
		return false, fmt.Errorf("netsh not available")
	}
	cmd := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", ruleName)
	//netsh advfirewall firewall show rule demo-example-5
	// Run the command and capture output
	output, err := cmd.Output()
	fmt.Println(string(output), err)

	// Convert output bytes to string
	outputStr := string(output)
	if string(output) != "" {
		// Check if the rule exists based on the output
		if strings.Contains(outputStr, "No rules match the specified criteria") {
			// Rule does not exist
			return false, nil
		}
	}

	if err != nil {
		// If there's an error, return false and the error
		return false, fmt.Errorf("error checking firewall rule: %v", err)
	}

	// Rule exists
	return true, nil
}

func firewallAnchorExistsDarwin(anchorName string) (bool, error) {

	if !manager.HasCommand("pfctl") {
		return false, fmt.Errorf("pfctl tool not available")
	}
	// Run pfctl command to list anchors
	cmd := exec.Command("pfctl", "-s", "Anchors")

	// Run the command and capture output
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("error running pfctl: %v", err)
	}

	// Convert output bytes to string and split into lines
	outputLines := strings.Split(string(output), "\n")

	// Check if the anchor exists in the list of anchors
	for _, line := range outputLines {
		if line == anchorName {
			return true, nil
		}
	}

	// Anchor does not exist
	return false, nil
}
