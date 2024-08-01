package firewall

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
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

		// Getting the protocol class for the given protocol
		proto, err := getProtocolClass(strings.ToLower(protocol))
		if err != nil {
			return err
		}

		if ok, err := firewallRuleExistsWindows(rulename); ok {
			log.Printf("firewall already exists with the given rule:%v", rulename)
			return nil
		} else {
			if err != nil {
				return err
			}
		}
		var cmdFirewall *exec.Cmd

		// post can be set only if the protocol is tcp or udp
		if (strings.ToLower(proto) == "tcp" || strings.ToLower(proto) == "udp") && port != "" {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+rulename, "dir="+direction, "action="+action, "protocol="+proto, "remoteip="+remoteip, "localport="+port)
		} else {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+rulename, "dir="+direction, "action="+action, "protocol="+proto, "remoteip="+remoteip)
		}

		err = cmdFirewall.Run()
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}
	case "linux":
		if !manager.HasCommand("iptables") {
			return fmt.Errorf("iptables command not found for operating system: %s", runtime.GOOS)
		}

		createChainCmd := exec.Command("iptables", "-N", rulename)
		if err := createChainCmd.Run(); err != nil {
			log.Println("Rule name already exists.Error creating rule name:", err)
			return err
		}
		cmdmap := make(map[string]string)
		args := make([]string, 0)

		cmdmap["-A"] = rulename
		args = append(args, "-A", rulename)

		if protocol == "all" || protocol == "any" {
			protocol = "all"
			args = append(args, "-p", "all")

		} else {
			args = append(args, "-p", protocol)
		}

		if port == "all" || port == "any" {
			port = ""
		} else {
			if direction == "in" {
				args = append(args, "--dport", port)
			} else if direction == "out" {
				//args = append(args, "--sport", port)
			}
		}

		if remoteip == "all" || remoteip == "any" {
			remoteip = ""
		} else {
			if direction == "in" {
				args = append(args, "-d", remoteip)
			} else if direction == "out" {
				//args = append(args, "-s", remoteip)
			}
		}

		if strings.ToLower((action)) == "allow" {
			action = "ACCEPT"
			args = append(args, "-j", "ACCEPT")
		}
		if strings.ToLower(action) == "block" {
			action = "DROP"
			args = append(args, "-j", "DROP")

		}

		args = append(args, "-m", "comment", "--comment", direction)

		var cmd *exec.Cmd

		cmd = exec.Command("iptables", args...)

		log.Println("Firewall Rule Command:", cmd.String())
		_, err := cmd.CombinedOutput()
		if err != nil {
			log.Println("Error setting up firewall rule:", err)
			return err
		}

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

		// cmd := exec.Command("sh", "-c", "echo", fmt.Sprintf("'%s'>>/etc/pf.conf", line))
		// err := cmd.Run()
		err := WriteFirewallRuleByAnchorDarwin(line)
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}

	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)

	}
	return nil
}

func (f *Firewall) UnSetFirewall(rulename string) error {
	if rulename == "" {
		return fmt.Errorf("invalid firewall rule name")
	}
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}

		if ok, err := firewallRuleExistsWindows(rulename); !ok {
			if err != nil {
				return fmt.Errorf("error in firewall rule:%v", rulename)
			}
			return fmt.Errorf("no firewall exists with the given rule:%v", rulename)
		}
		var cmdFirewall *exec.Cmd
		// post can be set only if the protocol is tcp or udp
		cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+rulename)

		err := cmdFirewall.Run()
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}

	case "linux":
		if !manager.HasCommand("iptables") {
			return fmt.Errorf("iptables command not found for operating system: %s", runtime.GOOS)
		}
		cmd := exec.Command("iptables", "-F", rulename)
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error while deleting firewall rule.Error-1:%v", err.Error())
		}
		log.Println("deleting rules associated with the rule name:", rulename)
		cmd = exec.Command("iptables", "-X", rulename)
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error while deleting firewall rule.Error-2:%v", err.Error())
		}

		log.Println("Firewall rule delated that is associated with the name:", rulename)

	case "darwin":
		if ok, err := firewallAnchorExistsDarwin(rulename); !ok || err != nil {
			return fmt.Errorf("firewall rule does not exist or some err.rule:%v,%v", rulename, err)
		} else {
			if err != nil {
				return err
			}
		}
		// sudo pfctl -a my_anchor -F rules
		// this deletes a rule based on the anchor. this application must ensure each rule has a saperate anchor
		err := RemoveFirewallRuleByAnchorDarwin(rulename)
		if err != nil {
			return fmt.Errorf("error while deleting firewall rule.Error:%v", err.Error())
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
		cmd := exec.Command("sudo", "iptables", "-L", rulename, "-n", "-v")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Println("Error:", err)
			return "", err
		}
		return string(output), nil
	case "darwin":
		if rulename == "all" || rulename == "any" {
			//cmd = exec.Command("pfctl", "-a", rulename, "-s", "rules")
			rules, err := GetFirewAllRulesDarwin()
			if err != nil {
				return "", fmt.Errorf("error fetching firewall rules:%v", err.Error())
			}
			output := ""
			for _, rule := range rules {
				output += rule + "\n"
			}
			return output, nil
		} else {
			rules, err := GetFirewallByAnchorDarwin(rulename)
			if err != nil {
				return "", fmt.Errorf("error fetching firewall rules:%v", err.Error())
			}
			// output := ""
			// for _, rule := range rules {
			// 	output += rule + "\n"
			// }
			// return output, nil
			if len(rules) > 0 {
				return rules[0], nil
			}
		}

	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return "", nil
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
		cmd := exec.Command("sudo", "iptables", "-L", rulename, "-n", "-v")
		output, err := cmd.Output()
		if err != nil {
			log.Println("Error:", err)
			return nil, err
		}
		return f.ToMap(string(output))

	case "darwin":
		rules, err := GetFirewallByAnchorDarwin(rulename)
		if err != nil {
			return nil, fmt.Errorf("error fetching firewall rules:%v", err.Error())
		}
		if len(rules) > 0 {
			return f.ToMap(rules[0]) //techinically there can be any number of rules per an anchor. But this tool must restrict while setFirewall
		}

	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil, nil
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
		ruleMap := parseFirewallRulesForLinux(output)
		if ruleMap == nil {
			return nil, fmt.Errorf("not implemented")
		}
		return ruleMap, nil

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
			//return outputMap, fmt.Errorf("no data found")
		}

	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil, nil
}

func firewallToMap(output string) (map[string]string, error) {
	outputMap := make(map[string]string, 0)
	switch runtime.GOOS {
	case "windows":
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			lineSep := strings.Split(line, ":")
			if len(lineSep) == 2 {
				switch lineSep[0] {
				case "Direction":
					outputMap["direction"] = strings.TrimSpace(strings.ToLower(lineSep[1]))
				case "Action":
					outputMap["action"] = strings.TrimSpace(strings.ToLower(lineSep[1]))
				case "Protocol":
					outputMap["protocol"] = strings.TrimSpace(strings.ToLower(lineSep[1]))
				case "RemoteIP":
					outputMap["remoteIP"] = strings.TrimSpace(strings.ToLower(lineSep[1]))
				case "RemotePort":
					outputMap["port"] = strings.TrimSpace(strings.ToLower(lineSep[1]))
				}
			}
		}
		if len(outputMap) > 0 {
			return outputMap, nil
		}
		return outputMap, fmt.Errorf("no data found")

	case "linux":
		ruleMap := parseFirewallRulesForLinux(output)
		if ruleMap == nil {
			return nil, fmt.Errorf("no data found")
		}
		return ruleMap, nil

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

	if !(strings.ToLower(action) == "allow" || strings.ToLower(action) == "block") {
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
	// Construct the netsh command to check if the firewall rule exists
	cmd := exec.Command("cmd", "/C", "netsh", "advfirewall", "firewall", "show", "rule", fmt.Sprintf("name=%s", ruleName))

	// Capture both stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Run the command
	err := cmd.Run()

	// Handle empty stdout and stderr with exit status 1
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			stdoutArr := strings.Split(stdout.String(), "\n")
			if exitError.ExitCode() == 1 && stdout.Len() > 0 && stderr.Len() == 0 {
				// Possible no rule found
				if strings.Contains(strings.TrimSpace(stdoutArr[1]), "No rules match the specified criteria") {
					return false, nil
				}
			}
		}
		// Return false and the error
		return false, fmt.Errorf("error checking firewall rule: %v, stderr: %v", err, stderr.String())
	}

	// Rule exists
	return true, nil
}

func firewallAnchorExistsDarwin(anchorName string) (bool, error) {
	if rules, err := GetFirewallByAnchorDarwin(anchorName); err != nil {
		return false, err
	} else if len(rules) > 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func firewallAnchorExistsLinux(chainName string) bool {
	if !manager.HasCommand("iptables-save") {
		log.Println("iptables-save tool not available")
		return false
	}

	// Fetch all iptables chains
	cmd := exec.Command("iptables-save")
	output, err := cmd.Output()
	if err != nil {
		log.Println("Error:", err)
		return false
	}

	// Split the output into lines
	lines := strings.Split(string(output), "\n")

	// Iterate over each line to find the chain
	for _, line := range lines {
		if strings.HasPrefix(line, ":"+chainName+" ") {
			return true
		}
	}
	return false
}

func parseFirewallRulesForLinux(output string) map[string]string {
	var ruleMap map[string]string
	lines := strings.Split(output, "\n")
	if len(lines) >= 3 {
		ruleMap = make(map[string]string)
		line := lines[2]
		fields := strings.Fields(line)
		if len(fields) > 7 && fields[0] != "Chain" {
			protocol := fields[3]
			port := ""
			remoteIP := ""
			action := ""
			if fields[2] == "DROP" {
				action = "block"
			} else if fields[2] == "ACCEPT" {
				action = "allow"
			}
			direction := ""
			if strings.Contains(line, "in") {
				direction = "in"
			} else if strings.Contains(line, "out") {
				direction = "out"
			}
			if strings.Contains(line, "dpt:") {
				remoteIP = fields[8]

			} else if strings.Contains(line, "spt:") {
				//remoteIP = fields[7]
			}

			for i := 2; i < len(fields); i++ {
				if strings.HasPrefix(fields[i], "dpt:") {
					port = strings.Split(fields[i], ":")[1]
				} else if strings.Contains(fields[i], "/") {
					//remoteIP = fields[i]
				} else if fields[i] == "dpt:" {
					// Handling cases where port is in separate field
					port = strings.Split(fields[i+1], ":")[1]
					i++ // Move to next field
				}
			}
			ruleMap["protocol"] = protocol
			ruleMap["port"] = port
			ruleMap["remoteIP"] = remoteIP
			ruleMap["action"] = action
			ruleMap["direction"] = direction
		}
	}
	return ruleMap
}

func (f *Firewall) IsFirewallExists(ruleName string) bool {
	switch runtime.GOOS {
	case "windows":
		b, err := firewallRuleExistsWindows(ruleName)
		if err != nil {
			log.Println("Error in reading firewall:", err)
		}
		return b
	case "linux":
		return firewallAnchorExistsLinux(ruleName)
	case "darwin":
		b, err := firewallAnchorExistsDarwin(ruleName)
		if err != nil {
			log.Println("Error in reading firewall:", err)
		}
		return b
	default:
		return false
	}
}

func GetFirewallByAnchorDarwin(anchorName string) ([]string, error) {
	var rules []string
	file, err := os.Open("/etc/pf.conf")
	if err != nil {
		log.Println("Error opening file:", err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Flag to indicate if the desired anchor is found
	foundAnchor := false
	for scanner.Scan() {
		line := scanner.Text()

		ln := strings.ReplaceAll(line, " ", "")
		if strings.Contains(ln, "anchor"+anchorName+"{") {
			//println(line)
			//println(ln)
			foundAnchor = true
		} else {
			if foundAnchor && ln != "}" {
				rules = append(rules, strings.TrimSpace(line))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
		return nil, err
	}

	return rules, nil
}

func GetFirewAllRulesDarwin() ([]string, error) {
	var rules []string
	file, err := os.Open("/etc/pf.conf")
	if err != nil {
		log.Println("Error opening file:", err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Flag to indicate if the desired anchor is found
	foundAnchor := false
	for scanner.Scan() {
		line := scanner.Text()

		ln := strings.ReplaceAll(line, " ", "")
		if strings.Contains(ln, "anchor") && strings.Contains(ln, "{") {
			//println(line)
			//println(ln)
			foundAnchor = true
		} else {
			if foundAnchor && ln != "}" {
				rules = append(rules, strings.TrimSpace(line))
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
		return nil, err
	}

	return rules, nil
}

func RemoveFirewallRuleByAnchorDarwin(anchorName string) error {
	file, err := os.Open("/etc/pf.conf")
	if err != nil {
		log.Println("Error opening file:", err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Flag to indicate if the desired anchor is found
	foundAnchor := false
	newContent := ""
	for scanner.Scan() {
		line := scanner.Text()

		ln := strings.ReplaceAll(line, " ", "")
		if strings.Contains(ln, "anchor"+anchorName+"{") {
			foundAnchor = true
			continue
		} else {
			if foundAnchor && ln == "}" {
				foundAnchor = false
				continue
			}
		}
		if !foundAnchor {
			newContent = newContent + line + "\n"
		}
	}
	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
		return err
	}

	// Write the modified content back to the file (caution advised)
	err = os.WriteFile("/etc/pf.conf", []byte(newContent), 0644)
	if err != nil {
		log.Println("Error writing file:", err)
		return err
	}

	log.Println("Anchor", anchorName, "removed successfully.")

	return nil
}

func WriteFirewallRuleByAnchorDarwin(rule string) error {
	// Open the file for appending and writing
	f, err := os.OpenFile("/etc/pf.conf", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		log.Println("Error opening file:", err)
		return err
	}
	defer f.Close()

	// Flag to indicate if the desired anchor is found
	_, err = f.Write([]byte(rule))
	if err != nil {
		log.Println("Error writing to file:", err)
		return err
	}
	return nil
}
