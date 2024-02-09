package manager

import (
	"errors"
	"log"
	"net"
	"os/exec"
	"strconv"
)

func GetActiveInterfaces() ([]string, error) {
	ifaces := make([]string, 0)
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("Error getting network interfaces:" + err.Error())

	}

	for _, iface := range interfaces {
		if (iface.Flags&net.FlagUp) != 0 && (iface.Flags&net.FlagLoopback) == 0 {
			ifaces = append(ifaces, iface.Name)
		}
	}

	return ifaces, nil
}

func IsValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}

func IsValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func IsValidPort(port string) bool {
	p, err := strconv.Atoi(port)
	if err != nil {
		return false
	}
	if p >= 0 && p <= 65535 {
		return true
	}
	return false
}

func IsValidIPAddressOrCIDR(input string) bool {
	// Check if the input is a valid IP address
	if IsValidIP(input) {
		return true
	}
	// Check if the input is a valid CIDR notation
	if IsValidCIDR(input) {
		return true
	}
	return false
}

func HasCommand(cmdName string) bool {
	_, err := exec.LookPath(cmdName)
	return err == nil
}

var ActiveInterfaces []string

func init() {
	var err error
	ActiveInterfaces, err = GetActiveInterfaces()
	if err != nil {
		log.Fatalln(err)
	}
}
