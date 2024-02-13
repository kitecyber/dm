package dm

import (
	_ "embed"
	"os/exec"
	"syscall"

	"github.com/getlantern/byteexec"
)

//go:embed binaries/windows_386/dm-cmd.exe
var dm []byte

func ensureElevatedOnDarwin(be *byteexec.Exec, prompt string, iconFullPath string) (err error) {
	return nil
}

func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}
