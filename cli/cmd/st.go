package cmd

import (
	"fmt"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/output"

	"github.com/fatih/color"
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

	_, payload := cmdutil.ExecuteCommand[api.StatPayload](ctx, "st", map[string]string{}, ExitWithError)
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
		payload.FileCount = files
		payload.FolderCount = folders
	}
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	fmt.Println()
	fmt.Println(color.CyanString("Storage Statistics"))
	fmt.Println()

	barWidth := 30
	filled := min(int(float64(barWidth)*float64(payload.UsedPercent)/100.0), barWidth)
	var bar strings.Builder
	for i := range barWidth {
		if i < filled {
			bar.WriteString("█")
		} else {
			bar.WriteString("░")
		}
	}

	usageColor := color.GreenString
	if payload.UsedPercent >= 90 {
		usageColor = color.RedString
	} else if payload.UsedPercent >= 70 {
		usageColor = color.YellowString
	}

	fmt.Printf("  %s %s %s\n", color.HiWhiteString("Usage:"), usageColor("[%s]", bar.String()), usageColor("%d%%", payload.UsedPercent))
	fmt.Printf("  %s %s / %s\n", color.HiWhiteString("Space:"), payload.UsedDisplay, payload.LimitDisplay)
	fmt.Printf("  %s %d files, %d folders\n", color.HiWhiteString("Items:"), payload.FileCount, payload.FolderCount)

	if payload.DailyUploadLimit > 0 {
		dailyUsed := payload.DailyUploadBytes
		fmt.Printf("  %s %s / %s today\n", color.HiWhiteString("Daily uploads:"), output.FormatSize(&dailyUsed), output.FormatSize(&payload.DailyUploadLimit))
	}

	if payload.VersionLimit != nil || payload.UploadRateLimit != nil || payload.DownloadRateLimit != nil || payload.ConcurrentUploads != nil {
		fmt.Println(color.CyanString("Tier Limits"))
		fmt.Println()
		if payload.VersionLimit != nil {
			fmt.Printf("  %s %d per file\n", color.HiWhiteString("Versions:"), *payload.VersionLimit)
		}
		if payload.UploadRateLimit != nil {
			fmt.Printf("  %s %s/s\n", color.HiWhiteString("Upload speed:"), output.FormatSize(payload.UploadRateLimit))
		}
		if payload.DownloadRateLimit != nil {
			fmt.Printf("  %s %s/s\n", color.HiWhiteString("Download speed:"), output.FormatSize(payload.DownloadRateLimit))
		}
		if payload.ConcurrentUploads != nil {
			fmt.Printf("  %s %d\n", color.HiWhiteString("Concurrent uploads:"), *payload.ConcurrentUploads)
		}
	}

	fmt.Println()
}
