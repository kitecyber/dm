package cmd

import (
	"fmt"
	"log"
	"os"
	"io/fs"

	"github.com/kardianos/osext"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(setUidCmd)
}

var setUidCmd = &cobra.Command{
	Use: "setuid",
	Run: func(cmd *cobra.Command, args []string) {
		err := SetUid()
		if err != nil {
			fmt.Println("setuid failed %v.", err.Error())
		}
	},
}

// set self binary as root/wheel and execute bits
func SetUid() error {
	self, err := osext.Executable()
	if err != nil {
		return err
	}

	err = os.Chown(self, 0, 0)
	if err != nil {
		log.Printf("change binary to root failed, binary %v, error %v", self, err)
		return err
	}

//	err = syscall.Chmod(self, syscall.S_IWUSR|syscall.S_IRWXU|unix.S_IRGRP|syscall.S_IXGRP|syscall.S_IROTH|syscall.S_IXOTH|syscall.S_ISUID)
	err = os.Chmod(self, 0755|fs.ModeSetuid)
	if err != nil {
		log.Printf("change binary to root failed, binary %v error %v", self, err)
		return err
	}

	log.Printf("set binary %v successfully", self)
	return nil
}
