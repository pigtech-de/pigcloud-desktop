package cmd

import (
	"fmt"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/spf13/cobra"
)

var (
	findType        string
	findLimit       int
	findAll         bool
	findRegex       bool
	findFixed       bool
	findIgnoreCase  bool
	findLargerThan  string
	findSmallerThan string
	findNewerThan   string
	findOlderThan   string
)

var findCmd = &cobra.Command{
	Use:     "fd <pattern> [path]",
	GroupID: GroupNav,
	Aliases: []string{"find"},
	Short:   "Find files by name",
	Long: `Search for files and directories matching a pattern.

By default the pattern uses glob matching:
  * matches any characters
  ? matches a single character

Use -E for regex matching or -F for literal substring matching.`,
	Example: `pc fd "*.pdf"                     # Glob: find PDF files
pc fd "report*" /docs              # Glob: search in /docs
pc fd -t d "project"               # Glob: directories only
pc fd -E "report_\d{4}" /docs      # Regex: report_2024 etc.
pc fd -Fi "readme" /               # Fixed: case-insensitive substring
pc fd "*" --larger-than 100M       # Files over 100 MB
pc fd "*.jpg" --newer-than 2026-01-01   # Recent photos`,
	Args:              cobra.RangeArgs(1, 2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		pattern := args[0]
		searchPath := ""
		if len(args) > 1 {
			searchPath = args[1]
		}
		runFind(pattern, searchPath)
	},
}

func init() {
	rootCmd.AddCommand(findCmd)
	findCmd.Flags().StringVarP(&findType, "type", "t", "", "filter by type: f (files) or d (directories)")
	findCmd.RegisterFlagCompletionFunc("type", func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		return []string{"f\tFiles only", "d\tDirectories only"}, cobra.ShellCompDirectiveNoFileComp
	})
	findCmd.Flags().IntVarP(&findLimit, "limit", "n", 100, "maximum number of results")
	findCmd.Flags().BoolVarP(&findAll, "all", "a", false, "include hidden files in results")
	findCmd.Flags().BoolVarP(&findRegex, "regex", "E", false, "treat pattern as regular expression")
	findCmd.Flags().BoolVarP(&findFixed, "fixed", "F", false, "treat pattern as literal substring")
	findCmd.Flags().BoolVarP(&findIgnoreCase, "ignore-case", "i", false, "case-insensitive matching")
	findCmd.Flags().StringVar(&findLargerThan, "larger-than", "", "only files larger than SIZE (e.g. 500K, 100M, 2G)")
	findCmd.Flags().StringVar(&findSmallerThan, "smaller-than", "", "only files smaller than SIZE")
	findCmd.Flags().StringVar(&findNewerThan, "newer-than", "", "only items modified on or after DATE (YYYY-MM-DD)")
	findCmd.Flags().StringVar(&findOlderThan, "older-than", "", "only items modified before DATE (YYYY-MM-DD)")
	findCmd.MarkFlagsMutuallyExclusive("regex", "fixed")
}

func runFind(pattern, searchPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(searchPath)
	options := map[string]string{
		"pattern": pattern,
		"source":  resolvedPath,
		"limit":   fmt.Sprintf("%d", findLimit),
	}
	if findType != "" {
		options["type"] = findType
	}
	if findAll {
		options["all"] = "true"
	}
	for opt, val := range map[string]string{
		"larger-than": findLargerThan, "smaller-than": findSmallerThan,
		"newer-than": findNewerThan, "older-than": findOlderThan,
	} {
		if val != "" {
			options[opt] = val
		}
	}

	if e2ee.HasE2EEKeys() {
		e2ee.AddPathTokensFor(options, resolvedPath, e2ee.SelfAndParent, ExitWithError)
		addRecursiveListingScope(ctx, options, resolvedPath, findAll)
	}

	_, payload := cmdutil.ExecuteCommand[api.FindPayload](ctx, "fd", options, ExitWithError)

	if !e2ee.EnsureNamesReadable() {
		return
	}

	nameByID := make(map[string]string, len(payload.Results))
	parentByID := make(map[string]string, len(payload.Results))
	for i := range payload.Results {
		entry := &payload.Results[i]
		if entry.E2EEDisplayName != "" {
			entry.Name = e2ee.DecryptE2EEName(entry.E2EEDisplayName)
		}
		if entry.ID != "" {
			nameByID[entry.ID] = entry.Name
			parentByID[entry.ID] = entry.ParentID
		}
	}

	basePath := strings.TrimRight(strings.TrimPrefix(resolvedPath, "/"), "/")
	buildPath := func(id string) string {
		segments := []string{}
		seen := make(map[string]struct{}, 8)
		for id != "" {
			if _, loop := seen[id]; loop {
				break
			}
			seen[id] = struct{}{}
			name, ok := nameByID[id]
			if !ok {
				break
			}
			segments = append([]string{name}, segments...)
			parent, ok := parentByID[id]
			if !ok || parent == "" {
				break
			}
			id = parent
		}
		prefix := "/"
		if basePath != "" {
			prefix = "/" + basePath + "/"
		}
		return prefix + strings.Join(segments, "/")
	}
	for i := range payload.Results {
		payload.Results[i].Path = buildPath(payload.Results[i].ID)
	}

	mode := cmdutil.MatchGlob
	if findRegex {
		mode = cmdutil.MatchRegex
	} else if findFixed {
		mode = cmdutil.MatchFixed
	}
	matcher, err := cmdutil.CompileMatcher(pattern, mode, findIgnoreCase)
	if err != nil {
		output.PrintError("Invalid pattern: " + err.Error())
		ExitWithError()
	}

	filtered := payload.Results[:0]
	for _, entry := range payload.Results {
		if entry.Filtered || entry.Name == "(encrypted)" {
			continue
		}
		if findType == "f" && entry.Type == "directory" {
			continue
		}
		if findType == "d" && entry.Type != "directory" {
			continue
		}
		if matcher.MatchString(entry.Name) {
			filtered = append(filtered, entry)
		}
	}
	payload.Results = filtered
	payload.Total = len(filtered)

	if cmdutil.PrintJSONOrContinue(GetJSONOutput(), payload) {
		return
	}

	if len(payload.Results) == 0 {
		output.PrintInfo("No matches found for pattern: " + pattern)
		return
	}

	table := output.Table([]string{"Name", "Path", "Type", "Size"})
	for _, entry := range payload.Results {
		name := output.FormatType(entry.Type, entry.Name)
		sizeValue := entry.Size
		if entry.PlaintextSize != nil {
			sizeValue = entry.PlaintextSize
		}
		size := output.FormatSize(sizeValue)
		table.Append([]string{name, entry.Path, entry.Type, size})
	}
	table.Render()

	fmt.Printf("\n%d results\n", len(payload.Results))
}
