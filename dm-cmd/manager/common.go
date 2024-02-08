package manager

import (
	"errors"
	"log"
	"net"
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

var ActiveInterfaces []string

func init() {
	var err error
	ActiveInterfaces, err = GetActiveInterfaces()
	if err != nil {
		log.Fatalln(err)
	}
}
