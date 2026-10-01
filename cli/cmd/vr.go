package cmd

import (
	"fmt"

	"pigcloud/internal/cmdutil"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:     "vr",
	GroupID: GroupTools,
	Aliases: []string{"version"},
	Short:   "Show version information",
	Long:    `Display the version, commit hash, and build date of the CLI.`,
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runVersion()
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion() {
	if GetJSONOutput() {
		result := map[string]string{
			"version": versionInfo.Version,
			"commit":  versionInfo.Commit,
			"date":    versionInfo.Date,
		}
		cmdutil.PrintJSONOrContinue(true, result)
		return
	}

	fmt.Printf("PigCloud CLI v%s\n", versionInfo.Version)
	if versionInfo.Commit != "" {
		fmt.Printf("  Commit: %s\n", versionInfo.Commit)
	}
	if versionInfo.Date != "" {
		fmt.Printf("  Built:  %s\n", versionInfo.Date)
	}
}
