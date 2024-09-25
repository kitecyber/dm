package firewall

import (
	"fmt"
	"strings"
)

// ProtocolClass represents a network protocol classification.
type ProtocolClass string

const (
	TCP ProtocolClass = "tcp"
	UDP ProtocolClass = "udp"
	ANY ProtocolClass = "any"
	ALL ProtocolClass = "all"
)

// Protocol classification mapping.
var protocolClassMap = map[string]ProtocolClass{
	"any":      ANY,
	"all":      ALL,
	"ssh":      TCP,
	"ftp":      TCP,
	"scp":      TCP,
	"sftp":     TCP,
	"rtp":      TCP,
	"rtcp":     TCP,
	"telnet":   TCP,
	"http":     TCP,
	"https":    TCP,
	"smtp":     TCP,
	"imap":     TCP,
	"pop":      TCP,
	"pop3":     TCP,
	"mysql":    TCP,
	"postgres": TCP,
	"redis":    TCP,
	"mongodb":  TCP,
	"ldap":     TCP,
	"snmp":     UDP,
	"dhcp":     UDP,
	"ntp":      UDP,
	"tftp":     UDP,
	"syslog":   UDP,
	"dns":      UDP,
	"gq":       UDP,
}

// getProtocolClass returns the ProtocolClass for a given protocol name.
func getProtocolClass(protocol string) (string, error) {
	protocol = strings.ToLower(protocol)
	if class, exists := protocolClassMap[protocol]; exists {
		return string(class), nil
	}
	return string(ANY), fmt.Errorf("protocol '%s' is not recognized", protocol)
}
