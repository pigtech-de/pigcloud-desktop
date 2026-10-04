package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
	"pigcloud/internal/progress"

	"github.com/spf13/cobra"
)

var vhCmd = &cobra.Command{
	Use:     "vh <file>",
	GroupID: GroupFiles,
	Aliases: []string{"versions"},
	Short:   "View and manage file version history",
	Long: `View, restore, or delete file version history.

Subcommands:
  vh <file>                    List versions (default)
  vh rs <file> <version-id>    Restore a specific version
  vh rm <version-id>           Delete a specific version`,
	Example: `pc vh /report.pdf             # List versions
pc vh rs /report.pdf 42       # Restore version #42
pc vh rm 42                   # Delete version #42`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runVersionList(args[0])
	},
}

var vhRestoreCmd = &cobra.Command{
	Use:   "rs <file> <version-id>",
	Short: "Restore a file to a specific version",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		runVersionRestore(args[0], args[1])
	},
}

var vhDlCmd = &cobra.Command{
	Use:   "dl <file> <version-id> [local-path]",
	Short: "Download a specific version",
	Example: `pc vh dl /report.pdf 42 ./        # Download version #42
pc vh dl /report.pdf 42 old.pdf  # Download to specific file`,
	Args: cobra.RangeArgs(2, 3),
	Run: func(cmd *cobra.Command, args []string) {
		localPath := "."
		if len(args) > 2 {
			localPath = args[2]
		}
		runVersionDownload(args[0], args[1], localPath)
	},
}

var vhPruneKeep int

var vhPruneCmd = &cobra.Command{
	Use:   "prune <file> --keep <N>",
	Short: "Delete all but the last N versions",
	Example: `pc vh prune /report.pdf --keep 3    # Keep last 3 versions
pc vh prune /report.pdf --keep 0    # Delete all versions`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runVersionPrune(args[0])
	},
}

var vhRmForce bool

var vhRmCmd = &cobra.Command{
	Use:   "rm <version-id>",
	Short: "Delete a specific version",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runVersionDelete(args[0])
	},
}

func init() {
	vhPruneCmd.Flags().IntVarP(&vhPruneKeep, "keep", "k", -1, "number of versions to keep")
	vhPruneCmd.MarkFlagRequired("keep")
	vhRmCmd.Flags().BoolVarP(&vhRmForce, "force", "f", false, "skip confirmation prompt")
	vhCmd.AddCommand(vhDlCmd, vhPruneCmd, vhRestoreCmd, vhRmCmd)
	rootCmd.AddCommand(vhCmd)
}

func runVersionList(filePath string) {
	resp, _, printed := cmdutil.RunPathCommand[api.VersionListPayload](cmdutil.PathCommand{
		Command: "vh", Path: filePath, Mode: "list", Scope: e2ee.SelfAndParent,
		JSON: GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func runVersionRestore(filePath, versionID string) {
	_, payload, printed := cmdutil.RunPathCommand[api.VersionActionPayload](cmdutil.PathCommand{
		Command: "vh", Path: filePath, Mode: "restore", Scope: e2ee.SelfAndParent,
		Options: map[string]string{"version-id": versionID},
		JSON:    GetJSONOutput(), ExitFn: ExitWithError,
	})
	if printed {
		return
	}

	if !GetQuietOutput() {
		output.PrintSuccess(fmt.Sprintf("Restored %s to v%d", output.PrintPath(payload.Path), payload.VersionNumber))
	}
}

func runVersionDelete(versionID string) {
	cmdutil.RequireLogin(ExitWithError)

	if !GetJSONOutput() && !GetQuietOutput() {
		if !cmdutil.ConfirmAction("Permanently delete version "+versionID+"?", vhRmForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	ctx, cancel := cmdutil.InterruptContext()
	defer cancel()

	_, payload := cmdutil.ExecuteCommand[api.VersionActionPayload](ctx, "vh", map[string]string{
		"mode":       "delete",
		"version-id": versionID,
	}, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if !GetQuietOutput() {
		output.PrintSuccess(fmt.Sprintf("Deleted version v%d", payload.VersionNumber))
	}
}

func runVersionDownload(filePath, versionID, localPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(filePath)
	options := map[string]string{
		"source":     resolvedPath,
		"mode":       "download",
		"version-id": versionID,
	}
	cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	fileName := filepath.Base(resolvedPath)
	if fileName == "" || fileName == "/" {
		fileName = "download"
	}
	ext := filepath.Ext(fileName)
	base := strings.TrimSuffix(fileName, ext)
	versionedName := fmt.Sprintf("%s_v%s%s", base, versionID, ext)

	stat, err := os.Stat(localPath)
	if err == nil && stat.IsDir() {
		localPath = filepath.Join(localPath, versionedName)
	} else if localPath == "." {
		localPath = versionedName
	}

	bar := progress.NewBar(-1, "Downloading "+versionedName)

	client := api.NewClient()
	dlResult, err := client.DownloadCommand(ctx, "vh", options, localPath, func(received, total int64) {
		if total > 0 {
			bar.ChangeMax64(total)
		}
		bar.Set64(received)
	})

	bar.Finish()

	if err != nil {
		output.PrintError("Download failed: " + err.Error())
		os.Remove(localPath)
		ExitWithError()
	}

	decryptDownloadedFile(localPath, dlResult)

	finalStat, _ := os.Stat(localPath)
	var size int64
	if finalStat != nil {
		size = finalStat.Size()
	}

	if !GetQuietOutput() {
		output.PrintSuccess(fmt.Sprintf("Downloaded v%s to %s", versionID, localPath))
		output.PrintInfo("Size: " + output.FormatSize(&size))
	}
}

func runVersionPrune(filePath string) {
	cmdutil.RequireLogin(ExitWithError)

	if vhPruneKeep < 0 {
		output.PrintError("--keep flag is required")
		ExitWithError()
	}

	resolvedPath := cmdutil.ResolvePath(filePath)

	if !GetJSONOutput() && !GetQuietOutput() {
		prompt := fmt.Sprintf("Delete all but the last %d version(s) of %s?", vhPruneKeep, resolvedPath)
		if !cmdutil.ConfirmAction(prompt, false) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	ctx, cancel := cmdutil.InterruptContext()
	defer cancel()

	options := map[string]string{
		"source": resolvedPath,
		"mode":   "prune",
		"keep":   fmt.Sprintf("%d", vhPruneKeep),
	}
	cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.VersionPrunePayload](ctx, "vh", options, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if payload.Pruned == 0 {
		output.PrintInfo("Nothing to prune")
	} else {
		output.PrintSuccess(fmt.Sprintf("Pruned %d version(s), keeping %d", payload.Pruned, payload.Kept))
	}
}
