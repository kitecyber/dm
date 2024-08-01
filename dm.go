package dm

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("dm")

	mu sync.Mutex
	be *byteexec.Exec
)

// EnsureHelperToolPresent checks if helper tool exists and extracts it if not.
// On Mac OS, it also checks and set the file's owner to root:wheel and the setuid bit,
// it will request user to input password through a dialog to gain the rights to do so.
// path: absolute or relative path of the file to be checked and generated if
// not exists. Note - relative paths are resolved relative to the system-
// specific folder for aplication resources.
// prompt: the message to be shown on the dialog.
// iconPath: the full path of the icon to be shown on the dialog.
func EnsureHelperToolPresent(path string, prompt string, iconFullPath string) (err error) {
	mu.Lock()
	defer mu.Unlock()
	if len(dm) == 0 {
		return fmt.Errorf("unable to find binary")
	}
	be, err = byteexec.New(dm, path)
	if err != nil {
		return fmt.Errorf("unable to extract helper tool: %v", err)
	}
	return ensureElevatedOnDarwin(be, prompt, iconFullPath)
}

// SetDNS sets primary and secondary dns
func SetDNS(iface, primary, secondary string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	var cmd *exec.Cmd
	if iface == "" {
		cmd = be.Command("dns", "--pd", primary, "--sd", secondary)
	} else {
		cmd = be.Command("dns", "--scope", "command", "--interface", iface, "--pd", primary, "--sd", secondary)
	}

	err := cmd.Run()
	if err != nil {
		log.Errorf("SetDNS failed: %v", err)
		return err
	}

	return nil
}

// UnSetDNS is to un-set dns
func UnSetDNS(iface string) error {
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	var cmd *exec.Cmd
	if iface == "" {
		cmd = be.Command("dns", "remove")
	} else {
		cmd = be.Command("dns", "--scope", "command", "--interface", iface, "remove")
	}

	err := cmd.Run()
	if err != nil {
		log.Errorf("RemoveDNS failed: %v", err)
		return err
	}

	return nil
}

// Show gets DNS information.
func ShowDNS(iface string) (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	var cmd *exec.Cmd
	if iface == "" {
		cmd = be.Command("dns", "show")
	} else {
		cmd = be.Command("dns", "--scope", "command", "show", "--interface", iface)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("ShowDNS failed: %v", err)
		return "", err
	}

	return string(out), nil
}

// Gets DNS information.
const (
	PRIMARY_PREFIX_SCOPE   = "Primary DNS: nameserver[0] :"
	SECONDARY_PREFIX_SCOPE = "Seconday DNS: nameserver[1] :"
	PRIMARY_PREFIX_GLOBE   = "Primary DNS:"
	SECONDARY_PREFIX_GLOBE = "Seconday DNS:"
)

func GetDNS(iface string) (primaryDNS string, secondaryDNS string, err error) {
	if be == nil {
		return "", "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	var cmd *exec.Cmd
	if iface == "" {
		cmd = be.Command("dns", "show")
	} else {
		cmd = be.Command("dns", "--scope", "command", "show", "--interface", iface)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Errorf("GetDNS failed: %v", err)
		return "", "", err
	}
	strs := strings.Split(string(out), "\n")
	var primary, secondary string = "", ""
	if len(strs) >= 2 {
		if iface == "" {
			priStr := strs[0]
			if len(priStr) > len(PRIMARY_PREFIX_GLOBE) {
				primary = string(priStr[len(PRIMARY_PREFIX_GLOBE):])
			}

			secStr := strs[1]
			if len(secStr) > len(SECONDARY_PREFIX_GLOBE) {
				secondary = string(secStr[len(SECONDARY_PREFIX_GLOBE):])
			}
		} else {
			priStr := strs[0]
			if len(priStr) > len(PRIMARY_PREFIX_SCOPE) {
				primary = string(priStr[len(PRIMARY_PREFIX_SCOPE):])
			}

			secStr := strs[1]
			if len(secStr) > len(SECONDARY_PREFIX_SCOPE) {
				secondary = string(secStr[len(SECONDARY_PREFIX_SCOPE):])
			}
		}

		primaryDNS = strings.TrimSpace(primary)
		secondaryDNS = strings.TrimSpace(secondary)
	} else {
		return "", "", fmt.Errorf("dns configuration has not found")
	}
	return primaryDNS, secondaryDNS, nil
}

// Gets DNS information.
func GetDNSToJson(iface string) (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	var cmd *exec.Cmd
	if iface == "" {
		cmd = be.Command("dns", "show")
	} else {
		cmd = be.Command("dns", "--scope", "command", "show", "--interface", iface)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	jsonStr := `{`
	strs := strings.Split(string(out), "\n")
	if len(strs) == 2 {
		primary := strings.Split(strs[0], ":")
		secondary := strings.Split(strs[1], ":")
		if len(primary) == 2 {
			jsonStr = jsonStr + `"primary":` + `"` + strings.TrimSpace(primary[1]) + `"`
		}
		if len(secondary) == 2 {
			jsonStr += `,"secondary":` + `"` + strings.TrimSpace(secondary[1]) + `"`
		}
		jsonStr = jsonStr + `}`

	} else {
		return "", fmt.Errorf("dns configuration has not found")
	}

	return jsonStr, nil
}

// SetFirewall sets firewall information
func SetFirewall(name, protocol, action, direction, remoteip, port string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("firewall", "-n", name, "-p", protocol, "-a", action, "-d", direction, "-r", port, "-i", remoteip)
	return cmd.Run()
}

func UnSetFirewall(name string) error {
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("firewall", "remove", "-n", name)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// Show get the firewall information based on name
func ShowFirewall(name string) (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("firewall", "show", "-n", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

func GetFirewall(name string) (action, direction, protocol, remoteIP, port string, err error) {
	if be == nil {
		return "", "", "", "", "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("firewall", "show", "-n", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", "", "", "", err
	}
	m, err := firewallToMap(string(out))
	if err != nil {
		return "", "", "", "", "", err
	}
	//fmt.Println(m)
	return m["action"], m["direction"], m["protocol"], m["remoteIP"], m["port"], nil
}

func IsFirewallExists(name string) (bool, error) {
	if be == nil {
		return false, fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("firewall", "exists", "-n", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return false, err
	}
	if string(out) == "Yes" {
		return true, nil
	} else if string(out) == "No" {
		return false, nil
	} else {
		return false, nil
	}
}

func GetFirewallToJson(name string) (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("firewall", "show", "-n", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	m, err := firewallToMap(string(out))
	if err != nil {
		return "", err
	}
	jsonData, err := json.Marshal(m)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func firewallToMap(output string) (map[string]string, error) {
	outputMap := make(map[string]string, 0)
	switch runtime.GOOS {
	case "windows":
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			//fmt.Println("---->", line)
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
