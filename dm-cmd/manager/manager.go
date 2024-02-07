package manager

import "net"

type IDNSDeviceManager interface {
	HasCommand(cmd string) bool
	SetDNS(iface string, primary string, secondary string) error
	GetActiveInterfaces() ([]string, error)
	GetDNS(string) (string, string, error)
	PostSetup() error
}

type IFirewallManager interface {
}

func IsValidIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil
}
