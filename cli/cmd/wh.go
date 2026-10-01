package cmd

import (
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"

	"github.com/spf13/cobra"
)

var whoamiCmd = &cobra.Command{
	Use:     "wh",
	GroupID: GroupAuth,
	Aliases: []string{"whoami"},
	Short:   "Show current user info",
	Long:    `Display information about the currently authenticated user.`,
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runWhoami()
	},
}

func init() {
	rootCmd.AddCommand(whoamiCmd)
}

func runWhoami() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resp, payload := cmdutil.ExecuteCommand[api.WhoamiPayload](ctx, "wh", map[string]string{}, ExitWithError)
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}
