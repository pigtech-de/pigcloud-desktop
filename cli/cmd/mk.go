package cmd

import (
	"path"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var mkParents bool

var mkCmd = &cobra.Command{
	Use:     "mk <path>",
	GroupID: GroupFiles,
	Aliases: []string{"mkdir"},
	Short:   "Create a new directory",
	Long: `Create a new directory in your cloud storage.

By default, the parent directory must already exist.
Use -p to create parent directories as needed.`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		runMk(args[0])
	},
}

func init() {
	rootCmd.AddCommand(mkCmd)
	mkCmd.Flags().BoolVarP(&mkParents, "parents", "p", false, "create parent directories as needed")
}

func runMk(targetPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	parentKey := writerParentKey()
	var payload api.CdPayload
	if mkParents {
		_, payload = ensureFolderChain[api.CdPayload](ctx, resolvedPath, parentKey)
	} else {
		options := map[string]string{"source": resolvedPath}
		fullPath, baseName := e2ee.ResolveAndBaseName(resolvedPath)
		cmdutil.AddE2eeNameFields(options, baseName, fullPath, ExitWithError)
		remint := sealNewNode(ctx, options, path.Dir(resolvedPath), parentKey)
		cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)
		_, payload = cmdutil.ExecuteCreate[api.CdPayload](ctx, "mk", options, remint, ExitWithError)
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if !GetQuietOutput() {
		output.PrintSuccess("Created " + output.PrintPath(resolvedPath))
	}
}
