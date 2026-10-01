package cmd

import (
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"

	"github.com/spf13/cobra"
)

var rcLimit string

var rcCmd = &cobra.Command{
	Use:     "rc",
	GroupID: GroupTools,
	Aliases: []string{"recents"},
	Short:   "List recently accessed files",
	Long:    `Show files and folders you've recently opened or accessed.`,
	Example: `pc rc              # List recent items
pc rc -n 10        # Show last 10 recent items`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runRecentList()
	},
}

func init() {
	rcCmd.Flags().StringVarP(&rcLimit, "limit", "n", "", "maximum number of items to show (default 50)")
	rootCmd.AddCommand(rcCmd)
}

func runRecentList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	options := map[string]string{}
	if rcLimit != "" {
		options["limit"] = rcLimit
	}

	resp, payload := cmdutil.ExecuteCommand[api.RecentListPayload](ctx, "rc", options, ExitWithError)

	for i := range payload.Recents {
		item := &payload.Recents[i]
		if item.E2EEDisplayName != "" {
			item.Name = e2ee.DecryptE2EEName(item.E2EEDisplayName)
		}
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}
