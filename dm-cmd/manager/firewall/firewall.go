//go:build linux || darwin
// +build linux darwin

package firewall

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/kitecyber/dm/dm-cmd/manager"
)

const Darwin_firewall_rules = "/etc/pf.conf"

var Protocols []string

type Firewall struct{}

func init() {
	Protocols = []string{"ANY", "ALL", "SSH", "FTP", "SFTP", "SCP", "UDP", "DNS", "DHCP", "IMAP", "SMTP", "POP", "SNPM", "SIP", "RTP", "RTCP", "TCP"}
}

func (f *Firewall) SetFirewall(ruleName, direction, action, protocol, remoteIP, port string) error {
	err := validateFirewallInput(ruleName, direction, action, protocol, remoteIP, port)
	if err != nil {
		return err
	}
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		proto, err := getProtocolClass(strings.ToLower(protocol))
		if err != nil {
			return err
		}

		if ok, err := firewallRuleExistsWindows(ruleName); ok {
			return fmt.Errorf("firewall already exists with the given rule:%v", ruleName)
		} else {
			if err != nil {
				return err
			}
		}
		var cmdFirewall *exec.Cmd
		// post can be set only if the protocol is tcp or udp
		if (strings.ToLower(proto) == "tcp" || strings.ToLower(proto) == "udp") && port != "" {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+ruleName, "dir="+direction, "action="+action, "protocol="+protocol, "remoteIP="+remoteIP, "localport="+port)
		} else {
			cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name="+ruleName, "dir="+direction, "action="+action, "protocol="+protocol, "remoteIP="+remoteIP)
		}

		cmdFirewall.SysProcAttr = &syscall.SysProcAttr{}
		cmdFirewall.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
		err = cmdFirewall.Run()
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}
	case "linux":
		if !manager.HasCommand("iptables") {
			return fmt.Errorf("iptables command not found for operating system: %s", runtime.GOOS)
		}

		createChainCmd := exec.Command("iptables", "-N", ruleName)
		createChainCmd.SysProcAttr = &syscall.SysProcAttr{}
		createChainCmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
		if output, err := createChainCmd.CombinedOutput(); err != nil {
			if strings.Contains(string(output), "Chain already exists") {
				log.Println("Rule name already exists. Skipping...")
				return nil
			}
			log.Println("Error fetching chain:", err)
			return err
		}
		cmdMap := make(map[string]string)
		args := make([]string, 0)

		cmdMap["-A"] = ruleName
		args = append(args, "-A", ruleName)

		// Getting the protocol class for the given protocol
		proto, err := getProtocolClass(strings.ToLower(protocol))
		if err != nil {
			return err
		}

		// Setting the protocol
		if proto == "all" || proto == "any" {
			args = append(args, "-p", "all") // default is all
		} else {
			args = append(args, "-p", proto) // else the given protocol class
		}

		// Setting the direction
		if port == "all" || port == "any" {
			port = ""
		} else {
			if direction == "in" {
				args = append(args, "--dport", port)
			} else if direction == "out" {
				//args = append(args, "--sport", port)
			}
		}

		// Setting the remote ip
		if remoteIP == "all" || remoteIP == "any" {
			remoteIP = ""
		} else {
			if direction == "in" {
				args = append(args, "-d", remoteIP)
			} else if direction == "out" {
				//args = append(args, "-s", remoteIP)
			}
		}

		if strings.ToLower(action) == "allow" {
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
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
		log.Println("Firewall Rule Command:", cmd.String())
		_, err = cmd.CombinedOutput()
		if err != nil {
			log.Println("command : ", cmd.String())
			log.Println("Error setting up firewall rule:", err)
			return err
		}
	case "darwin":
		if strings.ToLower(action) == "allow" {
			action = "pass"
		}

		if ok, err := firewallAnchorExistsDarwin(ruleName); ok {
			return fmt.Errorf("firewall already exists with the given rule:%v", ruleName)
		} else {
			if err != nil {
				return err
			}
		}

		proto, err := getProtocolClass(strings.ToLower(protocol))
		if err != nil {
			return err
		}

		// There is no rule name concept in darwin based systems.
		// anchors are used to group a rule or rules.
		line := fmt.Sprintln("anchor", ruleName, "{")
		// line = line + fmt.Sprintln(action, " ", direction, " ", "proto", " ", protocol, " ", "from", " ", "any", " ", "to", " ", remoteIP, " ", "port", " ", port)
		line = line + fmt.Sprintln("\t", action, direction, "proto", proto, "from", "any", "to", remoteIP, "port", port)
		line = line + "}"

		// cmd := exec.Command("sh", "-c", "echo", fmt.Sprintf("'%s'>>/etc/pf.conf", line))
		// err := cmd.Run()
		err = WriteFirewallRuleByAnchorDarwin(line)
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil
}

func (f *Firewall) UnSetFirewall(ruleName string) error {
	if ruleName == "" {
		return fmt.Errorf("invalid firewall rule name")
	}
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}

		if ok, err := firewallRuleExistsWindows(ruleName); !ok {
			if err != nil {
				return fmt.Errorf("error in firewall rule:%v", ruleName)
			}
			return fmt.Errorf("no firewall exists with the given rule:%v", ruleName)
		}
		var cmdFirewall *exec.Cmd
		// post can be set only if the protocol is tcp or udp
		cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ruleName)

		err := cmdFirewall.Run()
		if err != nil {
			return fmt.Errorf("error while setting firewall rule.Error:%v", err.Error())
		}
	case "linux":
		if !manager.HasCommand("iptables") {
			return fmt.Errorf("iptables command not found for operating system: %s", runtime.GOOS)
		}
		cmd := exec.Command("iptables", "-F", ruleName)
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error while deleting firewall rule.Error-1:%v", err.Error())
		}
		log.Println("deleting rules associated with the rule name:", ruleName)
		cmd = exec.Command("iptables", "-X", ruleName)
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error while deleting firewall rule.Error-2:%v", err.Error())
		}

		log.Println("Firewall rule deleted that is associated with the name:", ruleName)
	case "darwin":
		if ok, err := firewallAnchorExistsDarwin(ruleName); !ok || err != nil {
			return fmt.Errorf("firewall rule does not exist or some err.rule:%v,%v", ruleName, err)
		}
		// sudo pfctl -a my_anchor -F rules
		// this deletes a rule based on the anchor. this application must ensure each rule has a separate anchor
		err := RemoveFirewallRuleByAnchorDarwin(ruleName)
		if err != nil {
			return fmt.Errorf("error while deleting firewall rule.Error:%v", err.Error())
		}
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil
}

func (f *Firewall) ShowFirewall(ruleName string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return "", fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		if ruleName == "" {
			ruleName = "all"
		}
		var cmdFirewall *exec.Cmd
		cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
		output, err := cmdFirewall.Output()
		if err != nil {
			return "", fmt.Errorf("error while showing firewall rule.Error:%v", err.Error())
		}
		return string(output), nil
	case "linux":
		cmd := exec.Command("sudo", "iptables", "-L", ruleName, "-n", "-v")
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Println("Error:", err)
			return "", err
		}
		return string(output), nil
	case "darwin":
		if ruleName == "all" || ruleName == "any" {
			//cmd = exec.Command("pfctl", "-a", ruleName, "-s", "rules")
			rules, err := GetFirewallRulesDarwin()
			if err != nil {
				return "", fmt.Errorf("error fetching firewall rules:%v", err.Error())
			}
			output := ""
			for _, rule := range rules {
				output += rule + "\n"
			}
			return output, nil
		} else {
			rules, err := getFirewallByAnchorName(ruleName)
			if err != nil {
				return "", fmt.Errorf("error fetching firewall rules:%v", err.Error())
			}
			if len(rules) > 0 {
				return rules[0].Rule, nil
			}
		}
	default:
		return "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return "", nil
}

func (f *Firewall) GetFirewall(ruleName string) (firewall map[string]string, err error) {
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return nil, fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		if strings.ToLower(ruleName) == "all" || strings.ToLower(ruleName) == "any" {
			return nil, fmt.Errorf("invalid rule name")
		}
		var cmdFirewall *exec.Cmd
		cmdFirewall = exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name="+ruleName)
		output, err := cmdFirewall.Output()
		if err != nil {
			return nil, fmt.Errorf("error while showing firewall rule.Error:%v", err.Error())
		}
		return f.ToMap(string(output))
	case "linux":
		cmd := exec.Command("sudo", "iptables", "-L", ruleName, "-n", "-v")
		output, err := cmd.Output()
		if err != nil {
			log.Println("Error:", err)
			return nil, err
		}
		return f.ToMap(string(output))
	case "darwin":
		rules, err := getFirewallByAnchorName(ruleName)
		if err != nil {
			return nil, fmt.Errorf("error fetching firewall rules:%v", err.Error())
		}
		if len(rules) > 0 {
			return f.ToMap(rules[0].Rule) //technically there can be any number of rules per an anchor. But this tool must restrict while setFirewall
		}
	default:
		return nil, fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil, nil
}

// PostSetup any commands to run after setup.Like restart the servers etc.
func (f *Firewall) PostSetup() error {
	switch runtime.GOOS {
	case "windows":
	case "linux":
	case "darwin":
		if !manager.HasCommand("pfctl") {
			return fmt.Errorf("pfctl command not found for operating system: %s", runtime.GOOS)
		}
		cmd := exec.Command("pfctl", "-f", "/etc/pf.conf")
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uint32(0), Gid: uint32(0)}
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
	outputMap := make(map[string]string)
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
		stringSlice := strings.Split(output, " ")
		for i, str := range stringSlice {
			switch str {
			case "pass", "block":
				outputMap["action"] = str
			case "in", "out":
				outputMap["direction"] = str
			case "proto":
				if len(stringSlice) >= i+1 {
					outputMap["protocol"] = stringSlice[i+1]
				}
			case "port":
				if len(stringSlice) >= i+1 {
					outputMap["port"] = stringSlice[i+1]
				}
			case "to":
				if len(stringSlice) >= i+1 {
					outputMap["remoteIP"] = stringSlice[i+1]
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
	outputMap := make(map[string]string)
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
		stringSlice := strings.Split(output, " ")
		for i, str := range stringSlice {

			switch str {
			case "pass", "block":
				outputMap["action"] = str
			case "in", "out":
				outputMap["direction"] = str
			case "proto":
				if len(stringSlice) >= i+1 {
					outputMap["protocol"] = stringSlice[i+1]
				}
			case "port":
				if len(stringSlice) >= i+1 {
					outputMap["port"] = stringSlice[i+1]
				}
			case "to":
				if len(stringSlice) >= i+1 {
					outputMap["remoteIP"] = stringSlice[i+1]
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

func validateFirewallInput(ruleName, direction, action, protocol, remoteIP, port string) error {
	if ruleName == "" {
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
	if !(remoteIP != "" || strings.ToLower(remoteIP) == "all" || strings.ToLower(remoteIP) == "any") {
		return fmt.Errorf("invalid ip address or cidr notation")
	}

	if !(port != "" || strings.ToLower(port) == "all" || strings.ToLower(port) == "any") {
		return fmt.Errorf("invalid port")
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
	if rules, err := getFirewallByAnchorName(anchorName); err != nil {
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

// FirewallRule represents a firewall rule with its anchor name and rule details.
type FirewallRule struct {
	AnchorName string
	Rule       string
}

// getFirewallByAnchorName reads the /etc/pf.conf file and returns the firewall rules for a given anchor name.
func getFirewallByAnchorName(anchorName string) ([]FirewallRule, error) {
	file, err := os.Open(Darwin_firewall_rules)
	if err != nil {
		return nil, fmt.Errorf("failed to open pf.conf: %w", err)
	}
	defer file.Close()

	var rules []FirewallRule
	scanner := bufio.NewScanner(file)

	anchorRegex := regexp.MustCompile(`anchor\s+(\w+)\s+\{`)
	ruleRegex := regexp.MustCompile(`pass\s+in\s+proto\s+(\w+)\s+from\s+(\w+)\s+to\s+(\d+\.\d+\.\d+\.\d+)\s+port\s+(\d+)`)

	var currentAnchor string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if matches := anchorRegex.FindStringSubmatch(line); len(matches) > 1 {
			currentAnchor = matches[1]
		} else if matches := ruleRegex.FindStringSubmatch(line); len(matches) > 0 {
			if currentAnchor == anchorName {
				rules = append(rules, FirewallRule{
					AnchorName: currentAnchor,
					Rule:       line,
				})
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan pf.conf: %w", err)
	}

	return rules, nil
}

// GetFirewallRulesDarwin retrieves all firewall rules within anchors from /etc/pf.conf
func GetFirewallRulesDarwin() ([]string, error) {
	var rules []string
	file, err := os.Open(Darwin_firewall_rules)
	if err != nil {
		log.Println("Error opening file:", err)
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	foundAnchor := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		if strings.HasPrefix(trimmedLine, "anchor") && strings.HasSuffix(trimmedLine, "{") {
			foundAnchor = true
			continue
		}

		if foundAnchor {
			if trimmedLine == "}" {
				foundAnchor = false
				continue
			}
			rules = append(rules, trimmedLine)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
		return nil, err
	}

	return rules, nil
}

// RemoveFirewallRuleByAnchorDarwin removes firewall rules by anchor name from /etc/pf.conf
func RemoveFirewallRuleByAnchorDarwin(anchorName string) error {
	file, err := os.Open(Darwin_firewall_rules)
	if err != nil {
		log.Println("Error opening file:", err)
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	foundAnchor := false
	var newContent strings.Builder

	anchorStart := "anchor \"" + anchorName + "\" {"
	anchorEnd := "}"

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		if trimmedLine == anchorStart {
			foundAnchor = true
			continue
		}

		if foundAnchor {
			if trimmedLine == anchorEnd {
				foundAnchor = false
				continue
			}
		} else {
			newContent.WriteString(line + "\n")
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading file:", err)
		return err
	}

	// Create a backup of the original file
	err = os.WriteFile(Darwin_firewall_rules+".bak", []byte(newContent.String()), 0644)
	if err != nil {
		log.Println("Error creating backup file:", err)
		return err
	}

	// Write the modified content back to the file (caution advised)
	err = os.WriteFile(Darwin_firewall_rules, []byte(newContent.String()), 0644)
	if err != nil {
		log.Println("Error writing file:", err)
		return err
	}

	log.Println("Anchor", anchorName, "removed successfully.")

	return nil
}

// WriteFirewallRuleByAnchorDarwin writes a new firewall rule to /etc/pf.conf
func WriteFirewallRuleByAnchorDarwin(rule string) error {
	// Open the file for appending and writing
	f, err := os.OpenFile(Darwin_firewall_rules, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
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
