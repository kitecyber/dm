package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "dm-cmd v0.0.1",
	Long:  `dm-cmd v0.0.1.Currently in Active Development`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("dm-cmd v0.0.1")
	},
}
