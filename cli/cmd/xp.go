package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var xpOutput string

var xpCmd = &cobra.Command{
	Use:     "xp",
	GroupID: GroupTools,
	Aliases: []string{"export"},
	Short:   "Export all personal data",
	Long: `Download all personal data associated with your account as a JSON file.

Includes account info, file metadata, shares, activity log, and more.
File contents are NOT included (encrypted at rest and too large).`,
	Example: `pc xp                    # Export to pigcloud-export-YYYY-MM-DD.json
pc xp -o backup.json     # Export to a specific file`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runExport()
	},
}

func init() {
	xpCmd.Flags().StringVarP(&xpOutput, "output", "o", "", "output file path")
	rootCmd.AddCommand(xpCmd)
}

func runExport() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	if !GetQuietOutput() {
		output.PrintInfo("Exporting personal data...")
	}

	_, payload := cmdutil.ExecuteCommand[api.ExportPayload](ctx, "xp", map[string]string{}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	outPath := xpOutput
	if outPath == "" {
		outPath = fmt.Sprintf("pigcloud-export-%s.json", time.Now().Format("2006-01-02"))
	}

	data, err := json.MarshalIndent(payload.Export, "", "  ")
	if err != nil {
		output.PrintError("Failed to format export data: " + err.Error())
		ExitWithError()
	}

	if err := os.WriteFile(outPath, data, 0600); err != nil {
		output.PrintError("Failed to write file: " + err.Error())
		ExitWithError()
	}

	output.PrintSuccess(fmt.Sprintf("Exported to %s (%s)", outPath, output.FormatSize(ptrInt64(int64(len(data))))))
}

func ptrInt64(v int64) *int64 { return &v }
