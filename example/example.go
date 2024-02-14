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
	err = dm.OnFirewall("demo-example-1", "udp", "allow", "in", "12.13.14.15", "34343")
	if err != nil {
		fmt.Printf("Error set firewall: %s\n", err)
		return
	}

	err = dm.OnDNS("1.1.1.1", "8.8.4.4")
	if err != nil {
		fmt.Printf("Error set dns: %s\n", err)
		return
	}

	fmt.Println("Firewall and dns set, hit enter to continue (or kill the parent process)...")
	var i int
	fmt.Scanf("%d\n", &i)
}
