package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var (
	rmPermanent bool
	rmDry       bool
	rmForce     bool
)

var rmCmd = &cobra.Command{
	Use:     "rm <path>...",
	GroupID: GroupFiles,
	Aliases: []string{"remove"},
	Short:   "Delete files or directories",
	Long: `Delete files or directories from your cloud storage.

Accepts multiple paths and glob patterns (* ? [], last path segment only).

By default, items are moved to the recycling bin and can be restored later.
Items in the recycling bin are automatically deleted after 30 days.

Use --permanent to bypass the recycling bin and delete immediately.

Flags:
  -p, --permanent   Permanently delete, bypassing the recycling bin
  -d, --dry-run     Show what would be deleted without actually deleting
  -f, --force       Skip confirmation prompt`,
	Example: `pc rm /old-report.pdf              # Trash one file
pc rm a.txt b.txt c.txt            # Trash several
pc rm "*.tmp"                      # Trash everything matching a glob
pc rm "/logs/*.log" -p -f          # Permanently delete, no prompt`,
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runRm(args)
	},
}

func init() {
	rmCmd.Flags().BoolVarP(&rmPermanent, "permanent", "p", false, "Permanently delete, bypassing the recycling bin")
	rmCmd.Flags().BoolVarP(&rmDry, "dry-run", "d", false, "Show what would be deleted without actually deleting")
	rmCmd.Flags().BoolVarP(&rmForce, "force", "f", false, "Skip confirmation prompt")
	rootCmd.AddCommand(rmCmd)
}

func runRm(targets []string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	for _, target := range targets {
		if cmdutil.IsGlobArg(target) {
			runRmGlob(ctx, target)
		} else {
			runRmSingle(ctx, target)
		}
	}
}

func runRmGlob(ctx context.Context, pattern string) {
	matches := cmdutil.ExpandRemoteGlob(ctx, pattern, ExitWithError)
	if len(matches) == 0 {
		output.PrintError("No matches for pattern: " + pattern)
		ExitWithError()
	}

	if rmDry {
		for _, m := range matches {
			if rmPermanent {
				output.PrintInfo("[dry-run] Would permanently delete " + output.PrintPath(m.Path))
			} else {
				output.PrintInfo("[dry-run] Would move to recycling bin: " + output.PrintPath(m.Path))
			}
		}
		return
	}

	if !GetJSONOutput() && !GetQuietOutput() {
		prompt := fmt.Sprintf("Move %d items matching %q to the recycling bin?", len(matches), pattern)
		if rmPermanent {
			prompt = fmt.Sprintf("Permanently delete %d items matching %q? This cannot be undone.", len(matches), pattern)
		}
		if !cmdutil.ConfirmAction(prompt, rmForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	options := map[string]string{
		"source":       cmdutil.ResolvePath(pattern),
		"glob-matches": cmdutil.GlobMatchIDsJSON(matches),
	}
	if rmPermanent {
		options["permanent"] = "true"
	}

	_, payload := cmdutil.ExecuteCommand[api.RemovePayload](ctx, "rm", options, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	if !GetQuietOutput() {
		if payload.Permanent {
			output.PrintSuccess(fmt.Sprintf("Permanently deleted %d items matching %s", payload.Count, payload.Pattern))
		} else {
			output.PrintSuccess(fmt.Sprintf("Moved %d items matching %s to recycling bin", payload.Count, payload.Pattern))
		}
	}
}

func runRmSingle(ctx context.Context, targetPath string) {
	resolvedPath := cmdutil.ResolvePath(targetPath)

	if rmPermanent && !GetJSONOutput() && !GetQuietOutput() {
		prompt := fmt.Sprintf("Permanently delete %q? This cannot be undone.", filepath.Base(resolvedPath))
		if !cmdutil.ConfirmAction(prompt, rmForce) {
			output.PrintInfo("Cancelled")
			return
		}
	}

	options := map[string]string{
		"source": resolvedPath,
	}
	if rmPermanent {
		options["permanent"] = "true"
	}
	if rmDry {
		options["dry-run"] = "true"
	}

	e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.RemovePayload](ctx, "rm", options, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if payload.Dry {
		if payload.Permanent {
			output.PrintInfo("[dry-run] Would permanently delete " + output.PrintPath(payload.Path))
		} else {
			output.PrintInfo("[dry-run] Would move to recycling bin: " + output.PrintPath(payload.Path))
		}
		return
	}

	if !GetQuietOutput() {
		if payload.Count > 0 {
			if payload.Permanent {
				output.PrintSuccess(fmt.Sprintf("Permanently deleted %d items matching %s", payload.Count, payload.Pattern))
			} else {
				output.PrintSuccess(fmt.Sprintf("Moved %d items matching %s to recycling bin", payload.Count, payload.Pattern))
			}
		} else if payload.Permanent {
			output.PrintSuccess("Permanently deleted " + output.PrintPath(payload.Path))
		} else {
			output.PrintSuccess("Moved to recycling bin: " + output.PrintPath(payload.Path))
		}
	}
}
