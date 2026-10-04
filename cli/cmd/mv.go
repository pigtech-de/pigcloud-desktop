package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var mvDry bool

var propagateSubtreeNames = cmdutil.PropagateSubtreeNamesAtPath

var mvCmd = &cobra.Command{
	Use:     "mv <source> <target>",
	GroupID: GroupFiles,
	Aliases: []string{"move"},
	Short:   "Move or rename a file/directory",
	Long: `Move files or directories to a new location, or rename one.

If target is a directory, sources are moved into it.
If target doesn't exist, a single source is renamed to target.

Accepts multiple sources and glob patterns; the last argument is the target,
which must be an existing directory when moving more than one source.

Flags:
  -d, --dry-run   Show what would be moved without actually moving`,
	Example: `pc mv /draft.txt /final.txt        # Rename
pc mv a.txt b.txt /Archive/         # Move several into a directory
pc mv "*.log" /logs/                # Move by glob`,
	Args:              cobra.MinimumNArgs(2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runMvMulti(args)
	},
}

func runMvMulti(args []string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	target := args[len(args)-1]
	sources := cmdutil.ExpandPathArgs(ctx, args[:len(args)-1], ExitWithError)
	if len(sources) == 0 {
		output.PrintError("Nothing to move")
		ExitWithError()
	}
	if len(sources) > 1 {
		resolvedTarget := cmdutil.ResolvePath(target)
		if !cmdutil.IsExistingDirectory(ctx, resolvedTarget) {
			output.PrintError("Target must be an existing directory when moving multiple sources: " + target)
			ExitWithError()
		}
	}
	for _, source := range sources {
		runMv(source, target)
	}
}

func init() {
	mvCmd.Flags().BoolVarP(&mvDry, "dry-run", "d", false, "Show what would be moved without actually moving")
	rootCmd.AddCommand(mvCmd)
}

func runMv(source, target string) {
	relocate("mv", source, target, mvDry, func(ctx context.Context, landed string, payload api.MovePayload) {
		if payload.Dry {
			output.PrintInfo("[dry-run] Would move " + output.PrintPath(payload.Source) + " to " + output.PrintPath(payload.Target))
			return
		}
		if payload.Noop {
			output.PrintInfo("Source and target are the same, nothing to do")
			return
		}
		propagateSubtreeNames(ctx, landed, ExitWithError)
		if !GetQuietOutput() {
			if payload.Count > 0 {
				output.PrintSuccess(fmt.Sprintf("Moved %d items matching %s to %s", payload.Count, payload.Pattern, output.PrintPath(payload.Target)))
			} else {
				output.PrintSuccess("Moved " + output.PrintPath(payload.Source) + " to " + output.PrintPath(payload.Target))
			}
		}
	})
}

func relocate[T any](command, source, target string, dry bool, done func(ctx context.Context, landed string, payload T)) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedSource := cmdutil.ResolvePath(source)
	landed := cmdutil.ResolvePath(target)
	if cmdutil.IsExistingDirectory(ctx, landed) || strings.HasSuffix(target, "/") {
		landed = strings.TrimRight(landed, "/") + "/" + filepath.Base(resolvedSource)
	}

	options := map[string]string{"source": resolvedSource, "target": landed}
	if dry {
		options["dry-run"] = "true"
	}
	fullPath, baseName := e2ee.ResolveAndBaseName(landed)
	cmdutil.AddE2eeNameFields(options, baseName, fullPath, ExitWithError)
	cmdutil.AddPathTokensForAll(options, []string{resolvedSource, landed}, e2ee.SelfAndParent, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[T](ctx, command, options, ExitWithError)
	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	done(ctx, landed, payload)
}
