package manager

type IDNSDeviceManager interface {
	HasCommand(cmd string) bool
	SetDNS(iface string, primary string, secondary string) error
	GetDNS(string) (string, string, error)
	PostSetup() error
}

type IFirewallManager interface {
}
