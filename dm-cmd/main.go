package main

import "dm-cmd/cmd"

func main() {
	// println("Muruga! Help me")
	// globaldns := new(dm.GlobalDNS)
	// var id dm.IDNSDeviceManager
	// id = globaldns
	// fmt.Println(id.GetDNS("all"))
	// fmt.Println(id.SetDNS("", "8.8.8.8", "8.8.4.4"))
	// fmt.Println(id.GetDNS("all"))
	// fmt.Println("-->")
	// fmt.Println(getDNSServers())
	// fmt.Println(getDNS())
	cmd.Execute()
}

// func getDNSServers() ([]string, error) {
// 	// Get DNS information using nmcli command
// 	cmd := exec.Command("nmcli", "dev", "show")
// 	output, err := cmd.Output()
// 	fmt.Println(string(output))
// 	if err != nil {
// 		return nil, fmt.Errorf("error getting DNS information: %v", err)
// 	}

// 	// Parse output to extract DNS server addresses
// 	var dnsServers []string
// 	lines := strings.Split(string(output), "\n")
// 	for _, line := range lines {
// 		if strings.Contains(line, "DNS Servers") {
// 			fields := strings.Fields(line)
// 			if len(fields) >= 3 {
// 				dnsServers = append(dnsServers, fields[2])
// 			}
// 		}
// 	}

// 	return dnsServers, nil
// }

// func getDNS() (string, string, error) {
// 	// Execute the nmcli command to get DNS information
// 	cmd := exec.Command("nmcli", "dev", "show")
// 	output, err := cmd.Output()
// 	if err != nil {
// 		return "", "", fmt.Errorf("error running nmcli: %v", err)
// 	}

// 	// Parse the output to extract DNS information
// 	var primaryDNS, secondaryDNS string
// 	lines := strings.Split(string(output), "\n")
// 	for _, line := range lines {
// 		if strings.Contains(line, "IP4.DNS[1]:") {
// 			fields := strings.Fields(line)
// 			if len(fields) >= 2 {
// 				primaryDNS = fields[1]
// 			}
// 		} else if strings.Contains(line, "IP4.DNS[2]:") {
// 			fields := strings.Fields(line)
// 			if len(fields) >= 2 {
// 				secondaryDNS = fields[1]
// 			}
// 		}
// 	}

// 	return primaryDNS, secondaryDNS, nil
// }
