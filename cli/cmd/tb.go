package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var (
	tbSort       string
	tbType       string
	tbEmptyForce bool
)

var tbCmd = &cobra.Command{
	Use:     "tb",
	GroupID: GroupFiles,
	Aliases: []string{"trash"},
	Short:   "Manage recycling bin",
	Long: `Show all items in the recycling bin.

Use 'rs <node-id>' to restore items or 'tb empty' to empty the bin.`,
	Example: `pc tb                    # List trash contents
pc rs <node-id>          # Restore an item by node ID
pc tb empty              # Empty the bin`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runTrashList()
	},
}

var tbEmptyCmd = &cobra.Command{
	Use:   "empty",
	Short: "Permanently delete all items in the recycling bin",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runEmptyTrash()
	},
}

var tbListCmd = &cobra.Command{
	Use:   "ls",
	Short: "List recycling bin contents",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runTrashList()
	},
}

func init() {
	tbEmptyCmd.Flags().BoolVarP(&tbEmptyForce, "force", "f", false, "Skip confirmation prompt")
	tbCmd.AddCommand(tbListCmd, tbEmptyCmd)
	rootCmd.AddCommand(tbCmd)
	tbCmd.Flags().StringVarP(&tbSort, "sort", "S", "", "sort by: name, size, or time")
	tbCmd.RegisterFlagCompletionFunc("sort", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"name\tSort by name", "size\tSort by size", "time\tSort by deletion time"}, cobra.ShellCompDirectiveNoFileComp
	})
	tbCmd.Flags().StringVarP(&tbType, "type", "t", "", "filter by type: f (files) or d (directories)")
	tbCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"f\tFiles only", "d\tDirectories only"}, cobra.ShellCompDirectiveNoFileComp
	})
}

func runTrashList() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	options := map[string]string{}
	if tbSort != "" {
		options["sort"] = tbSort
	}
	if tbType != "" {
		options["type"] = tbType
	}

	resp, payload := cmdutil.ExecuteCommand[api.TrashListPayload](ctx, "tb", options, ExitWithError)

	for i := range payload.Items {
		item := &payload.Items[i]
		if item.E2EEDisplayName != "" {
			item.Name = e2ee.DecryptE2EEName(item.E2EEDisplayName)
		}
		if item.Type == "" && item.ItemType != "" {
			item.Type = item.ItemType
		}
		if item.Size == 0 && item.FileSize > 0 {
			item.Size = item.FileSize
		}
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runEmptyTrash() {
	cmdutil.RequireLogin(ExitWithError)

	if !GetJSONOutput() && !GetQuietOutput() {
		if !cmdutil.ConfirmAction("Permanently delete all items in the recycling bin? This cannot be undone.", tbEmptyForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	_, payload := cmdutil.ExecuteCommand[api.EmptyTrashPayload](ctx, "et", map[string]string{}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	fmt.Printf("Emptied recycling bin (%d items deleted)\n", payload.Count)
}
