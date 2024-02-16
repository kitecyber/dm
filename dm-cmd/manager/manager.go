package manager

type IDNSDeviceManager interface {
	SetDNS(iface string, primary string, secondary string) error
	GetDNS(string) (string, string, error)
	UnSetDNS(iface string) error
	PostSetup() error
}

type IFirewallManager interface {
	SetFirewall(rulename, direction, action, protocol, remoteip, port string) error
	UnSetFirewall(rulename string) error
	ShowFirewall(rulename string) (string, error)
	GetFirewall(rulename string) (map[string]string, error)
	PostSetup() error
}
