package cmd

import (
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"

	"github.com/spf13/cobra"
)

var inCmd = &cobra.Command{
	Use:     "in [path]",
	GroupID: GroupTools,
	Aliases: []string{"info"},
	Short:   "Show file or directory info",
	Long: `Display detailed information about a file or directory.

Shows size, dates, type, sharing status, and recipients for shared folders.`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		targetPath := ""
		if len(args) > 0 {
			targetPath = args[0]
		}
		runInfo(targetPath)
	},
}

func init() {
	rootCmd.AddCommand(inCmd)
}

func runInfo(targetPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	options := map[string]string{"source": resolvedPath}
	if e2ee.HasE2EEKeys() {
		e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)
		addChildScope(ctx, options, resolvedPath)
	}
	resp, payload := cmdutil.ExecuteCommand[api.InfoPayload](ctx, "in", options, ExitWithError)
	details := payload.Details

	if details.E2EEDisplayName != "" {
		details.Name = e2ee.DecryptE2EEName(details.E2EEDisplayName)
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), details) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}
