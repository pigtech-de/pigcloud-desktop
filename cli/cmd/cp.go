package cmd

import (
	"path/filepath"
	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
	"strings"

	"github.com/spf13/cobra"
)

var cpDry bool

var cpCmd = &cobra.Command{
	Use:               "cp <source> <target>",
	GroupID:           GroupFiles,
	Aliases:           []string{"copy"},
	Short:             "Copy a file or directory",
	Args:              cobra.ExactArgs(2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runCopy(args[0], args[1])
	},
}

func init() {
	cpCmd.Flags().BoolVarP(&cpDry, "dry-run", "d", false, "Preview what would be copied without making changes")
	rootCmd.AddCommand(cpCmd)
}

func runCopy(source, target string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedSource := cmdutil.ResolvePath(source)
	resolvedTarget := cmdutil.ResolvePath(target)

	targetTrailingSlash := strings.HasSuffix(target, "/")
	effectiveTarget := resolvedTarget
	if cmdutil.IsExistingDirectory(ctx, resolvedTarget) || targetTrailingSlash {
		sourceBase := filepath.Base(resolvedSource)
		if resolvedTarget == "/" {
			effectiveTarget = "/" + sourceBase
		} else {
			effectiveTarget = strings.TrimRight(resolvedTarget, "/") + "/" + sourceBase
		}
	}

	options := map[string]string{
		"source": resolvedSource,
		"target": effectiveTarget,
	}
	if cpDry {
		options["dry-run"] = "true"
	}

	fullPath, baseName := e2ee.ResolveAndBaseName(effectiveTarget)
	e2ee.AddE2eeNameFields(options, baseName, fullPath, ExitWithError)

	e2ee.AddPathTokensForAll(options, []string{resolvedSource, effectiveTarget}, e2ee.SelfAndParent, ExitWithError)

	_, payload := cmdutil.ExecuteCommand[api.CopyPayload](ctx, "cp", options, ExitWithError)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if payload.Dry {
		output.PrintInfo("[dry-run] Would copy " + output.PrintPath(payload.Path) + " to " + output.PrintPath(payload.Target))
		return
	}

	if !GetQuietOutput() {
		output.PrintSuccess("Copied " + output.PrintPath(payload.Path) + " to " + output.PrintPath(payload.Target))
	}
}
