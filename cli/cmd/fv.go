package cmd

import (
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var fvCmd = &cobra.Command{
	Use:     "fv [path]",
	GroupID: GroupFiles,
	Aliases: []string{"favorite"},
	Short:   "Manage favorites",
	Long: `Manage your favorites list.

Without arguments, lists all favorites.
With a path argument, toggles the favorite status.
A file shared with you is addressed /<owner>:<nodeId>, the id ls prints.`,
	Example: `pc fv                  # List favorites
pc fv /Documents         # Toggle favorite
pc fv /alice:9f3c...     # Toggle favorite on a shared file
pc fv add "*.jpg"        # Add all matches to favorites
pc fv rm /Documents      # Remove from favorites`,
	Args:              cobra.ArbitraryArgs,
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) == 0 {
			runFavoriteList()
			return
		}
		cmdutil.ForEachExpandedPath(args, runFavoriteToggle, ExitWithError)
	},
}

var fvListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List all favorites",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runFavoriteList()
	},
}

var fvAddCmd = &cobra.Command{
	Use:               "add <path>...",
	Short:             "Add paths to favorites",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		cmdutil.ForEachExpandedPath(args, runFavoriteAdd, ExitWithError)
	},
}

var fvRmCmd = &cobra.Command{
	Use:               "rm <path>...",
	Short:             "Remove paths from favorites",
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		cmdutil.ForEachExpandedPath(args, runFavoriteRemove, ExitWithError)
	},
}

func init() {
	fvCmd.AddCommand(fvListCmd, fvAddCmd, fvRmCmd)
	rootCmd.AddCommand(fvCmd)
}

func runFavoriteToggle(path string) {
	_, payload, printed := cmdutil.RunPathCommand[api.FavoritePayload](cmdutil.PathCommand{
		Command: "fv", Path: path, Mode: "toggle", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	if payload.Action == "added" {
		output.PrintSuccess("Added " + output.PrintPath(payload.Path) + " to favorites")
	} else {
		output.PrintSuccess("Removed " + output.PrintPath(payload.Path) + " from favorites")
	}
}

func runFavoriteList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()
	options := map[string]string{"mode": "list"}
	resp, payload := cmdutil.ExecuteCommand[api.FavoriteListPayload](ctx, "fv", options, ExitWithError)

	for i := range payload.Favorites {
		fav := &payload.Favorites[i]
		fav.Name = e2ee.ResolveName(fav.E2EEDisplayName, fav.Name)
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runFavoriteAdd(path string) {
	_, payload, printed := cmdutil.RunPathCommand[api.FavoritePayload](cmdutil.PathCommand{
		Command: "fv", Path: path, Mode: "add", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	output.PrintSuccess("Added " + output.PrintPath(payload.Path) + " to favorites")
}

func runFavoriteRemove(path string) {
	_, payload, printed := cmdutil.RunPathCommand[api.FavoritePayload](cmdutil.PathCommand{
		Command: "fv", Path: path, Mode: "remove", JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	output.PrintSuccess("Removed " + output.PrintPath(payload.Path) + " from favorites")
}
