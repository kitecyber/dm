package dns

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/kitecyber/dm/dm-cmd/manager"
)

type GlobalDNS struct{}

// there is no significance for iface here as it is system level DNS. This is kept to satisfy the interface
func (gd *GlobalDNS) SetDNS(iface, primaryDNS, secondaryDNS string) error {
	var cmd *exec.Cmd
	if !manager.IsValidIP(primaryDNS) {
		return fmt.Errorf("invalid primary dns ip address %v", primaryDNS)
	}
	if !manager.IsValidIP(secondaryDNS) {
		return fmt.Errorf("invalid secondary dns ip address %v", secondaryDNS)
	}
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		hasOneSet := false
		for _, iface := range manager.ActiveInterfaces {
			cmdPrimary := exec.Command("netsh", "interface", "ipv4", "set", "dns", "name="+iface, "source=static", "addr="+primaryDNS)
			cmdSecondary := exec.Command("netsh", "interface", "ipv4", "add", "dns", "name="+iface, "addr="+secondaryDNS, "index=2")
			err1 := cmdPrimary.Run()
			if err1 != nil {
				log.Printf("Error setting Primary DNS for the interface:%v.Error:%v", iface, err1.Error())
			}
			err2 := cmdSecondary.Run()
			if err2 != nil {
				log.Printf("Error setting Secondary DNS for the interface:%v.Error:%v", iface, err2.Error())
			}
			if err1 == nil && err2 == nil {
				hasOneSet = true
			}
		}
		if !hasOneSet {
			return fmt.Errorf("error setting DNS servers")
		}
	case "linux", "darwin":
		if !manager.HasCommand("sh") {
			return fmt.Errorf("sh command not for operating system: %s", runtime.GOOS)
		}
		cmd = exec.Command("sh", "-c", fmt.Sprintf("echo 'nameserver %s\nnameserver %s' > /etc/resolv.conf", primaryDNS, secondaryDNS))
		err := cmd.Run()
		if err != nil {
			return fmt.Errorf("error setting secondary DNS: %v", err)
		}

	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil
}

// there is no significance for iface here as it is system level DNS. This is kept to satisfy the interface
func (gd *GlobalDNS) GetDNS(iface string) (string, string, error) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		if !manager.HasCommand("netsh") {
			return "", "", fmt.Errorf("netsh command not found for operating system: %s", runtime.GOOS)
		}
		return gd.getDNSWindows() // get primary and secondary dns for windows

	case "linux", "darwin":
		if !manager.HasCommand("cat") {
			return "", "", fmt.Errorf("cat command not for operating system: %s", runtime.GOOS)
		}
		cmd = exec.Command("cat", "/etc/resolv.conf")
		output, err := cmd.Output()
		if err != nil {
			return "", "", err
		}
		return gd.parseDNSOutput(string(output))

	default:
		return "", "", fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
}

func (gd *GlobalDNS) getDNSWindows() (string, string, error) {
	// Get DNS settings using netsh command
	cmd := exec.Command("netsh", "interface", "ipv4", "show", "dns")
	output, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("error getting DNS settings: %v", err)
	}
	// Parse output to extract DNS server addresses
	lines := strings.Split(string(output), "\r\n")
	primaryDNS := ""
	secondaryDNS := ""
	pattern := `\b(?:\d{1,3}\.){3}\d{1,3}\b`
	regex := regexp.MustCompile(pattern)
	for _, line := range lines {
		if strings.Contains(line, "Configuration for interface") || strings.Contains(line, "None") || strings.Contains(line, "Primary only") {
			continue
		} else {
			//fmt.Println(line)
			matches := regex.FindAllString(line, -1)
			for _, match := range matches {
				if primaryDNS == "" {
					primaryDNS = match
				} else {
					secondaryDNS = match
				}
			}
		}
		if primaryDNS != "" && secondaryDNS != "" {
			return primaryDNS, secondaryDNS, nil
		}

	}
	return primaryDNS, secondaryDNS, nil
}

func (gd *GlobalDNS) parseDNSOutput(output string) (string, string, error) {
	lines := strings.Split(output, "\n")
	var primaryDNS, secondaryDNS string

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if primaryDNS == "" {
				primaryDNS = fields[1]
			} else if secondaryDNS == "" {
				secondaryDNS = fields[1]
			}
		}
	}

	if primaryDNS == "" {
		return "", "", fmt.Errorf("unable to determine primary DNS")
	}

	return primaryDNS, secondaryDNS, nil
}

func (gd *GlobalDNS) PostSetup() error {
	return nil
}
