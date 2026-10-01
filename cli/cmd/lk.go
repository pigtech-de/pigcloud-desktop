package cmd

import (
	"pigcloud/internal/agent"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount"
	"pigcloud/internal/output"
	"pigcloud/internal/tree"

	"github.com/spf13/cobra"
)

var lkCmd = &cobra.Command{
	Use:     "lk",
	GroupID: GroupAuth,
	Aliases: []string{"lock"},
	Short:   "Lock encryption keys",
	Long: `Stop the background key agent and clear decrypted keys from memory.

After locking, commands that access encrypted files will prompt for your
password again (or require 'pc uk' to unlock).`,
	Example: "pc lk    # Lock encryption keys",
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runLock()
	},
}

func init() {
	rootCmd.AddCommand(lkCmd)
}

func runLock() {
	cmdutil.RequireLogin(ExitWithError)

	if !agent.IsRunning() {
		output.PrintInfo("Not unlocked")
		return
	}

	for _, m := range mount.ListMounts() {
		if mount.IsMountReachable(m) {
			output.PrintInfo("Active mount at " + m.MountPoint + ": stop with 'pc mn stop' first, or the mount will lose E2EE access on restart")
		}
	}

	if err := agent.Shutdown(); err != nil {
		output.PrintError("Failed to stop agent: " + err.Error())
		ExitWithError()
	}

	e2ee.ClearCachedKey()
	output.PrintSuccess("Locked")
	tree.ClearCache()
}
