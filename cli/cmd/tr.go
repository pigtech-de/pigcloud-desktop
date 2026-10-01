package cmd

import (
	"fmt"
	"os"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"
	"pigcloud/internal/tree"

	"github.com/spf13/cobra"
)

var (
	treeDepth    int
	treeDirsOnly bool
	treeAll      bool
)

var treeCmd = &cobra.Command{
	Use:     "tr [path]",
	GroupID: GroupNav,
	Aliases: []string{"tree"},
	Short:   "Display directory tree",
	Long: `Display a tree view of directories and files.

If no path is specified, shows the tree from the current working directory.`,
	Args:              cobra.MaximumNArgs(1),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		targetPath := ""
		if len(args) > 0 {
			targetPath = args[0]
		}
		runTree(targetPath)
	},
}

func init() {
	rootCmd.AddCommand(treeCmd)
	treeCmd.Flags().IntVarP(&treeDepth, "depth", "L", 3, "maximum display depth")
	treeCmd.Flags().BoolVarP(&treeDirsOnly, "dirs", "d", false, "show directories only")
	treeCmd.Flags().BoolVarP(&treeAll, "all", "a", false, "show hidden files")
}

func runTree(targetPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(targetPath)

	if built := loadClientTree(ctx); built != nil {
		if folderID, ok := folderIDFor(built, resolvedPath); ok {
			renderLocalTree(built, folderID, resolvedPath)
			return
		}
	}

	options := map[string]string{
		"source": resolvedPath,
		"depth":  fmt.Sprintf("%d", treeDepth),
	}
	if treeDirsOnly {
		options["dirs"] = "true"
	}
	if treeAll {
		options["all"] = "true"
	}

	e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	resp, payload := cmdutil.ExecuteCommand[api.TreePayload](ctx, "tr", options, ExitWithError)

	decryptTreeEntries(payload.Entries)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}
	cmdutil.RenderServerDisplay(resp)
}

func decryptTreeEntries(entries []api.TreeEntry) {
	for i := range entries {
		if entries[i].E2EEDisplayName != "" {
			entries[i].Name = e2ee.DecryptE2EEName(entries[i].E2EEDisplayName)
		}
		if len(entries[i].Children) > 0 {
			decryptTreeEntries(entries[i].Children)
		}
	}
}

func renderLocalTree(built *tree.Tree, folderID, resolvedPath string) {
	maxDepth := treeDepth
	if maxDepth < 0 {
		maxDepth = 3
	} else if maxDepth > 10 {
		maxDepth = 10
	}
	entries := localTreeEntries(built, folderID, maxDepth, treeDirsOnly, treeAll)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), api.TreePayload{Path: resolvedPath, Entries: entries}) {
		return
	}

	dirs, files := countTreeItems(entries)
	blocks := []output.DisplayBlock{
		{Type: "heading", Style: "path", Text: resolvedPath},
		{Type: "tree", Tree: localDisplayTree(entries)},
		{Type: "text"},
		{Type: "text", Text: fmt.Sprintf("%d directories, %d files", dirs, files)},
	}
	output.RenderDisplay(os.Stdout, blocks, func(name string) string { return name })
}

func localTreeEntries(built *tree.Tree, folderID string, maxDepth int, dirsOnly, showAll bool) []api.TreeEntry {
	if maxDepth <= 0 {
		return nil
	}
	var out []api.TreeEntry
	for _, child := range built.Children(folderID) {
		if child.Trashed {
			continue
		}
		if !showAll && child.Hidden {
			continue
		}
		if dirsOnly && !child.IsDir {
			continue
		}
		entry := api.TreeEntry{Name: child.Name, Type: "file"}
		if child.IsDir {
			entry.Type = "directory"
			entry.Children = localTreeEntries(built, child.ID, maxDepth-1, dirsOnly, showAll)
		}
		out = append(out, entry)
	}
	return out
}

func localDisplayTree(entries []api.TreeEntry) []output.DisplayTreeNode {
	nodes := make([]output.DisplayTreeNode, 0, len(entries))
	for _, entry := range entries {
		nodes = append(nodes, output.DisplayTreeNode{
			Name:     entry.Name,
			FileType: entry.Type,
			Children: localDisplayTree(entry.Children),
		})
	}
	return nodes
}

func countTreeItems(entries []api.TreeEntry) (dirs, files int) {
	for _, entry := range entries {
		if entry.Type == "directory" {
			dirs++
		} else {
			files++
		}
		if len(entry.Children) > 0 {
			childDirs, childFiles := countTreeItems(entry.Children)
			dirs += childDirs
			files += childFiles
		}
	}
	return
}
