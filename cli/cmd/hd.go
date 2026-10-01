package cmd

import (
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var hdCmd = &cobra.Command{
	Use:     "hd [path]",
	GroupID: GroupFiles,
	Aliases: []string{"hide"},
	Short:   "Hide or unhide files and folders",
	Long: `Manage hidden files and folders.

Without arguments, lists all hidden items.
With a path argument, toggles the hidden status.`,
	Example: `pc hd                  # List hidden items
pc hd /Private           # Toggle hidden
pc hd add "*.bak"        # Hide all matches
pc hd rm /Private        # Unhide`,
	Args:              cobra.ArbitraryArgs,
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			runHideList()
			return
		}
		cmdutil.ForEachExpandedPath(args, runHideToggle, ExitWithError)
	},
}

var hdAddCmd = &cobra.Command{
	Use:               "add <path>...",
	Short:             "Hide files or folders",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		cmdutil.ForEachExpandedPath(args, runHide, ExitWithError)
	},
}

var hdRmCmd = &cobra.Command{
	Use:               "rm <path>...",
	Short:             "Unhide files or folders",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		cmdutil.ForEachExpandedPath(args, runUnhide, ExitWithError)
	},
}

var hdListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List all hidden items",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runHideList()
	},
}

func init() {
	hdCmd.AddCommand(hdAddCmd, hdRmCmd, hdListCmd)
	rootCmd.AddCommand(hdCmd)
}

func runHideToggle(path string) {
	_, payload, printed := cmdutil.RunPathCommand[api.HidePayload](cmdutil.PathCommand{
		Command: "hd", Path: path, Mode: "toggle", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	if payload.Hidden {
		output.PrintSuccess("Hidden " + output.PrintPath(payload.Path))
	} else {
		output.PrintSuccess("Unhidden " + output.PrintPath(payload.Path))
	}
}

func runHide(path string) {
	_, payload, printed := cmdutil.RunPathCommand[api.HidePayload](cmdutil.PathCommand{
		Command: "hd", Path: path, Mode: "hide", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	output.PrintSuccess("Hidden " + output.PrintPath(payload.Path))
}

func runUnhide(path string) {
	_, payload, printed := cmdutil.RunPathCommand[api.HidePayload](cmdutil.PathCommand{
		Command: "hd", Path: path, Mode: "unhide", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	output.PrintSuccess("Unhidden " + output.PrintPath(payload.Path))
}

func runHideList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()
	resp, payload := cmdutil.ExecuteCommand[api.HideListPayload](ctx, "hd", map[string]string{
		"mode": "list",
	}, ExitWithError)

	for i := range payload.Items {
		item := &payload.Items[i]
		if item.E2EEDisplayName != "" {
			item.Name = e2ee.DecryptE2EEName(item.E2EEDisplayName)
		}
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}
