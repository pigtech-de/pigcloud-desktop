package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/filetypes"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var duCmd = &cobra.Command{
	Use:     "du",
	GroupID: GroupTools,
	Aliases: []string{"usage"},
	Short:   "Show storage breakdown by file type",
	Long: `Analyze storage usage broken down by file type.

Shows how much space each category (images, documents, videos, etc.) uses.`,
	Example: `pc du    # Show storage breakdown`,
	Args:    cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		runDiskUsage()
	},
}

func init() {
	rootCmd.AddCommand(duCmd)
}

func classifyByName(name string) string {
	ext := strings.TrimPrefix(filepath.Ext(strings.ToLower(name)), ".")
	return filetypes.TypeOf(ext)
}

func runDiskUsage() {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	options := map[string]string{}
	addSubtreeScope(ctx, options, "/")

	_, payload := cmdutil.ExecuteCommand[api.DiskUsagePayload](ctx, "du", options, ExitWithError)

	if len(payload.Files) == 0 {
		if GetJSONOutput() {
			cmdutil.PrintJSONOrContinue(true, struct {
				Breakdown []api.StorageCategory `json:"breakdown"`
			}{Breakdown: []api.StorageCategory{}})
			return
		}
		output.PrintInfo("No files found")
		return
	}

	buckets := map[string]*api.StorageCategory{}
	for _, f := range payload.Files {
		fileType := "other"
		name := e2ee.DecryptE2EEName(f.E2EEDisplayName)
		if name != "(encrypted)" {
			fileType = classifyByName(name)
		}
		cat, ok := buckets[fileType]
		if !ok {
			cat = &api.StorageCategory{Type: fileType}
			buckets[fileType] = cat
		}
		cat.Size += f.Size
		cat.Count++
	}

	breakdown := make([]api.StorageCategory, 0, len(buckets))
	for _, cat := range buckets {
		breakdown = append(breakdown, *cat)
	}
	for i := 0; i < len(breakdown); i++ {
		for j := i + 1; j < len(breakdown); j++ {
			if breakdown[j].Size > breakdown[i].Size {
				breakdown[i], breakdown[j] = breakdown[j], breakdown[i]
			}
		}
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), struct {
		Breakdown  []api.StorageCategory `json:"breakdown"`
		TrashSize  int64                 `json:"trashSize"`
		TrashCount int                   `json:"trashCount,omitempty"`
	}{Breakdown: breakdown, TrashSize: payload.TrashSize, TrashCount: payload.TrashCount}) {
		return
	}

	fmt.Println(color.HiWhiteString("Storage Breakdown"))
	fmt.Println()

	var totalSize int64
	var totalCount int
	for _, cat := range breakdown {
		totalSize += cat.Size
		totalCount += cat.Count
	}

	table := output.Table([]string{"Type", "Files", "Size", "%"})
	for _, cat := range breakdown {
		size := output.FormatSize(&cat.Size)
		pct := ""
		if totalSize > 0 {
			pct = fmt.Sprintf("%.1f%%", float64(cat.Size)/float64(totalSize)*100)
		}
		table.Append([]string{cat.Type, fmt.Sprintf("%d", cat.Count), size, pct})
	}
	table.Render()
	fmt.Printf("\n%d files, %s total\n", totalCount, output.FormatSize(&totalSize))

	if payload.TrashSize > 0 {
		fmt.Printf("Trash: %s\n", output.FormatSize(&payload.TrashSize))
	}
}
