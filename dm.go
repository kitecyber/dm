package dm

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/golog"
)

var (
	log = golog.LoggerFor("dm")

	mu sync.Mutex
	be *byteexec.Exec
)

// EnsureHelperToolPresent checks if helper tool exists and extracts it if not.
// On Mac OS, it also checks and set the file's owner to root:wheel and the setuid bit,
// it will request user to input password through a dialog to gain the rights to do so.
// path: absolute or relative path of the file to be checked and generated if
// not exists. Note - relative paths are resolved relative to the system-
// specific folder for aplication resources.
// prompt: the message to be shown on the dialog.
// iconPath: the full path of the icon to be shown on the dialog.
func EnsureHelperToolPresent(path string, prompt string, iconFullPath string) (err error) {
	mu.Lock()
	defer mu.Unlock()
	if len(dm) == 0 {
		return fmt.Errorf("unable to find binary: %v")
	}
	be, err = byteexec.New(dm, path)
	if err != nil {
		return fmt.Errorf("unable to extract helper tool: %v", err)
	}
	return ensureElevatedOnDarwin(be, prompt, iconFullPath)
}

// OnDNS sets primary and secondary dns
func OnDNS(primary, secondary string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("dns", "--pd", primary, "--sd", secondary)
	return cmd.Run()
}

// Show gets DNS information.
func ShowDNS() (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("dns", "show")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// OnFirewall sets firewall information
func OnFirewall(name, protocol, action, direction, remoteip, port string) error {
	mu.Lock()
	defer mu.Unlock()
	if be == nil {
		return fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("firewall", "-n", name, "-p", protocol, "-a", action, "-d", direction, "-r", port, "-i", remoteip)
	fmt.Println(cmd.String())
	return cmd.Run()
}

// Show get the firewall information based on name
func ShowFirewall(name string) (string, error) {
	if be == nil {
		return "", fmt.Errorf("call EnsureHelperToolPresent() first")
	}

	cmd := be.Command("firewall", "show", "-n", name)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(out), nil
}

type resultType struct {
	out []byte
	err error
}

func allEquals(expected string, actual string) bool {
	if (expected == "") != (strings.TrimSpace(actual) == "") { // XOR
		return false
	}
	lines := strings.Split(actual, "\n")
	for _, l := range lines {
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && trimmed != expected {
			return false
		}
	}
	return true
}
