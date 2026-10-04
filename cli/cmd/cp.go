package cmd

import (
	"context"
	"pigcloud/internal/api"
	"pigcloud/internal/completion"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var cpDry bool

var cpCmd = &cobra.Command{
	Use:               "cp <source> <target>",
	GroupID:           GroupFiles,
	Aliases:           []string{"copy"},
	Short:             "Copy a file or directory",
	Args:              cobra.ExactArgs(2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runCopy(args[0], args[1])
	},
}

func init() {
	cpCmd.Flags().BoolVarP(&cpDry, "dry-run", "d", false, "Preview what would be copied without making changes")
	rootCmd.AddCommand(cpCmd)
}

func runCopy(source, target string) {
	relocate("cp", source, target, cpDry, func(ctx context.Context, landed string, payload api.CopyPayload) {
		if payload.Dry {
			output.PrintInfo("[dry-run] Would copy " + output.PrintPath(payload.Path) + " to " + output.PrintPath(payload.Target))
			return
		}
		propagateSubtreeNames(ctx, landed, ExitWithError)
		if !GetQuietOutput() {
			output.PrintSuccess("Copied " + output.PrintPath(payload.Path) + " to " + output.PrintPath(payload.Target))
		}
	})
}
