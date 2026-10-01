package cmd

import (
	"fmt"

	"pigcloud/internal/cmdutil"
	"pigcloud/internal/config"

	"github.com/spf13/cobra"
)

var pwdCmd = &cobra.Command{
	Use:     "wd",
	GroupID: GroupNav,
	Aliases: []string{"pwd"},
	Short:   "Print working directory",
	Long:    `Display the current working directory in your cloud storage.`,
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runPwd()
	},
}

func init() {
	rootCmd.AddCommand(pwdCmd)
}

func runPwd() {
	cmdutil.RequireLogin(ExitWithError)

	cwd := config.GetCwd()

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), map[string]string{"path": cwd}) {
		return
	}

	fmt.Println(cwd)
}
