package dm

import (
	_ "embed"
	"fmt"
	"os/exec"
	"syscall"

	"github.com/getlantern/byteexec"
	"github.com/getlantern/elevate"
)

//go:embed binaries/dm-cmd_darwin_amd64
var dm []byte

func ensureElevatedOnDarwin(be *byteexec.Exec, prompt string, iconFullPath string) (err error) {
	var s syscall.Stat_t
	// we just checked its existence, not bother checking specific error again
	if err = syscall.Stat(be.Filename, &s); err != nil {
		return fmt.Errorf("error starting helper tool %s: %v", be.Filename, err)
	}
	if s.Mode&syscall.S_ISUID > 0 && s.Uid == 0 && s.Gid == 0 {
		log.Tracef("%v is already owned by root:wheel and has setuid bit on", be.Filename)
		return
	}
	cmd := elevate.WithPrompt(prompt).WithIcon(iconFullPath).Command(be.Filename, "setuid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("unable to execute %v: %s\n%s", cmd.Path, err, string(out))
	}

	return nil
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}
