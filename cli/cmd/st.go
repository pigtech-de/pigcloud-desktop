package cmd

import (
	"strconv"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"

	"github.com/spf13/cobra"
)

var statCmd = &cobra.Command{
	Use:     "st",
	GroupID: GroupTools,
	Aliases: []string{"stats"},
	Short:   "Show storage statistics",
	Long:    `Display storage usage statistics for your account.`,
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runStat()
	},
}

func init() {
	rootCmd.AddCommand(statCmd)
}

func runStat() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	options := map[string]string{}
	if built := loadClientTree(ctx); built != nil {
		files, folders := 0, 0
		for _, id := range built.Descendants("") {
			node, ok := built.Get(id)
			if !ok || node.Trashed {
				continue
			}
			if node.IsDir {
				folders++
			} else {
				files++
			}
		}
		options["file_count"] = strconv.Itoa(files)
		options["folder_count"] = strconv.Itoa(folders)
	}

	resp, payload := cmdutil.ExecuteCommand[api.StatPayload](ctx, "st", options, ExitWithError)
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}
