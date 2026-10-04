package cmd

import (
	"fmt"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"

	"github.com/spf13/cobra"
)

var (
	lsLong      bool
	lsRecursive bool
	lsSortSize  bool
	lsSortTime  bool
	lsAll       bool
	lsLimit     int
	lsOffset    int
	lsFilters   sizeDateFilters
)

var sizeDateFlags = [...]struct{ name, usage string }{
	{"larger-than", "only files larger than SIZE (e.g. 500K, 100M, 2G)"},
	{"smaller-than", "only files smaller than SIZE"},
	{"newer-than", "only items modified on or after DATE (YYYY-MM-DD)"},
	{"older-than", "only items modified before DATE (YYYY-MM-DD)"},
}

type sizeDateFilters [len(sizeDateFlags)]string

func (f *sizeDateFilters) register(cmd *cobra.Command) {
	for i, flag := range sizeDateFlags {
		cmd.Flags().StringVar(&f[i], flag.name, "", flag.usage)
	}
}

func (f *sizeDateFilters) apply(options map[string]string) {
	for i, flag := range sizeDateFlags {
		if f[i] != "" {
			options[flag.name] = f[i]
		}
	}
}

var lsCmd = &cobra.Command{
	Use:     "ls [path]",
	GroupID: GroupNav,
	Aliases: []string{"list"},
	Short:   "List files and directories",
	Example: "pc ls -l -S                      # List with details, sorted by size",
	Long: `List files and directories in your cloud storage.

If no path is specified, lists the current working directory.
Use 'pc cd' to change the working directory.

Flags:
  -l    Show detailed information (size in bytes, full timestamps)
  -R    List directories recursively
  -S    Sort by file size (largest first)
  -t    Sort by modification time (newest first)`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		targetPath := ""
		if len(args) > 0 {
			targetPath = args[0]
		}
		runLs(targetPath)
	},
}

func init() {
	rootCmd.AddCommand(lsCmd)
	lsCmd.Flags().BoolVarP(&lsLong, "long", "l", false, "use detailed listing format")
	lsCmd.Flags().BoolVarP(&lsRecursive, "recursive", "R", false, "list directories recursively")
	lsCmd.Flags().BoolVarP(&lsSortSize, "sort-size", "S", false, "sort by file size, largest first")
	lsCmd.Flags().BoolVarP(&lsSortTime, "sort-time", "t", false, "sort by modification time, newest first")
	lsCmd.Flags().BoolVarP(&lsAll, "all", "a", false, "show hidden files")
	lsCmd.Flags().IntVarP(&lsLimit, "limit", "n", 0, "maximum number of items to show")
	lsCmd.Flags().IntVarP(&lsOffset, "offset", "o", 0, "number of items to skip")
	lsFilters.register(lsCmd)
}

func runLs(targetPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)
	options := map[string]string{"source": resolvedPath}
	if lsLong {
		options["long"] = "true"
	}
	if lsRecursive {
		options["recursive"] = "true"
	}
	if lsSortSize {
		options["sort"] = "size"
	} else if lsSortTime {
		options["sort"] = "time"
	}
	if lsAll {
		options["all"] = "true"
	}
	if lsLimit > 0 {
		options["limit"] = fmt.Sprintf("%d", lsLimit)
	}
	if lsOffset > 0 {
		options["offset"] = fmt.Sprintf("%d", lsOffset)
	}
	lsFilters.apply(options)

	if e2ee.HasE2EEKeys() {
		cmdutil.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)
		if lsRecursive {
			addRecursiveListingScope(ctx, options, resolvedPath, lsAll)
		} else {
			addChildScope(ctx, options, resolvedPath)
		}
	}

	resp, payload := cmdutil.ExecuteCommand[api.ListPayload](ctx, "ls", options, ExitWithError)

	for i := range payload.Entries {
		entry := &payload.Entries[i]
		entry.Name = e2ee.ResolveName(entry.E2EEDisplayName, entry.Name)
		if entry.E2EEDisplayName != "" && entry.Type == "directory" {
			entry.Path = "/" + entry.Name
		}
	}

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	cmdutil.RenderServerDisplay(resp)
}
