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
		var cmdFirewall *exec.Cmd
		// post can be set only if the protocol is tcp or udp
		if (strings.ToLower(protocol) == "tcp" || strings.ToLower(protocol) == "udp") && port != "" {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+rulename, "dir="+direction, "action="+action, "protocol="+protocol, "remoteip="+remoteip, "localport="+port)
		} else {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+rulename, "dir="+direction, "action="+action, "protocol="+protocol, "remoteip="+remoteip)
		}

		// to test format on windows
		// if strings.ToLower(action) == "allow" {
		// 	action = "pass"
		// }
		// // There is no rule name concept in darwin based systems.
		// // anchors are used to group a rule or rules.
		// line := fmt.Sprintln("anchor", rulename, "{")
		// // line = line + fmt.Sprintln(action, " ", direction, " ", "proto", " ", protocol, " ", "from", " ", "any", " ", "to", " ", remoteip, " ", "port", " ", port)
		// line = line + fmt.Sprintln("\t", action, direction, "proto", protocol, "from", "any", "to", remoteip, "port", port)
		// line = line + "}"
		// fmt.Println(line)

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
	return "", nil
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
