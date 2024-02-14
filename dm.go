package dm

import (
	_ "embed"
	"fmt"
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
		return fmt.Errorf("unable to find binary: %v")
	}
	be, err = byteexec.New(dm, path)
	if err != nil {
		return fmt.Errorf("unable to extract helper tool: %v", err)
	}
	return ensureElevatedOnDarwin(be, prompt, iconFullPath)
}

// OnDNS sets primary and secondary dns
func OnDNS(primary, secondary string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("dns", "--pd", primary, "--sd", secondary)
	return cmd.Run()
}

// Show gets DNS information.
func ShowDNS() (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("dns", "show")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Gets DNS information.
func GetDNS() (primaryDNS string, secondaryDNS string, err error) {
	if be == nil {
		return "", "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}
	cmd := be.Command("dns", "show")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", "", err
	}
	strs := strings.Split(string(out), "\n")
	if len(strs) == 2 {
		primary := strings.Split(strs[0], ":")
		secondary := strings.Split(strs[1], ":")
		if len(primary) == 2 {
			primaryDNS = strings.TrimSpace(primary[1])
		}
		if len(secondary) == 2 {
			secondaryDNS = strings.TrimSpace(secondary[1])
		}

	} else {
		return "", "", fmt.Errorf("dns configuration has not found")
	}
	return primaryDNS, secondaryDNS, nil
}

// OnFirewall sets firewall information
func OnFirewall(name, protocol, action, direction, remoteip, port string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("firewall", "-n", name, "-p", protocol, "-a", action, "-d", direction, "-r", port, "-i", remoteip)
	return cmd.Run()
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
