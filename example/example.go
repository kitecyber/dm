package main

import (
	"fmt"
	"path/filepath"

	"github.com/kitecyber/dm"

	"github.com/getlantern/golog"
)

var log = golog.LoggerFor("example")

func main() {
	helperFullPath := "dm-cmd"
	iconFullPath, _ := filepath.Abs("./icon.png")
	log.Debugf("Using icon at %v", iconFullPath)
	err := dm.EnsureHelperToolPresent(helperFullPath, "Input your password and save the world!", iconFullPath)
	if err != nil {
		fmt.Printf("Error EnsureHelperToolPresent: %s\n", err)
		return
	}
	err = dm.SetFirewall("demo-firewall-1", "udp", "allow", "in", "12.13.14.15", "34343")
	if err != nil {
		fmt.Printf("Error set firewall: %s\n", err)
		return
	}
	action, direction, protocol, remoteIP, port, err := dm.GetFirewall("demo-firewall-1")
	if err != nil {
		fmt.Println("Error show firewall:", err.Error())
		return
	}
	fmt.Println("action:", action, "direction:", direction, "protocol:", protocol, "remoteIP:", remoteIP, "port:", port)

	err = dm.UnSetFirewall("demo-firewall-1")

	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("firewall successfully un-set")
	}
	err = dm.SetDNS("1.1.1.1", "8.8.4.4")
	if err != nil {
		fmt.Printf("Error set dns: %s\n", err)
		return
	}

	out, err := dm.ShowDNS()
	if err != nil {
		fmt.Printf("Error set dns: %s\n", err)
		return
	}
	fmt.Println(string(out))
	primary, secondary, err := dm.GetDNS()
	if err != nil {
		fmt.Printf("Error fetching dns: %s\n", err)
		return
	}
	fmt.Println(primary, secondary)

	fmt.Println("Firewall and dns set, hit enter to continue (or kill the parent process)...")
	var i int
	fmt.Scanf("%d\n", &i)
}
