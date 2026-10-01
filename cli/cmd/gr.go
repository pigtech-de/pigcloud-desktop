package cmd

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/completion"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/filetypes"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var (
	grRecursive  bool
	grFilesOnly  bool
	grIgnoreCase bool
	grMaxResults int
	grRegex      bool
	grFixed      bool
	grAllFiles   bool
)

var grCmd = &cobra.Command{
	Use:     "gr <pattern> [path]",
	GroupID: GroupNav,
	Aliases: []string{"grep"},
	Short:   "Search file contents",
	Long: `Search for a pattern across your files.

Default mode walks the sealed full-text index; no file content is
downloaded, only the per-file sealed token index (built on upload +
backfill). Multiple tokens (space-separated) are AND'd, case-insensitive,
two-character minimum. Files that aren't indexed yet are silently skipped;
the web client backfills older uploads automatically.

Passing a [path] argument, -A/--all-files, -E (regex), or -F (fixed
substring) switches to the per-file download + line-scan path. Slower
but scopes to the given path, covers unindexed files, and supports regex
or substring matches that cross token boundaries.`,
	Example: `pc gr "TODO"                       # fast index search across all files
pc gr "function authenticate"      # AND tokens
pc gr -l "TODO"                    # show only file names
pc gr "fmt.Println" /src           # scoped scan (path arg triggers full scan)
pc gr -E "func\s+\w+" /src         # regex (triggers full scan)
pc gr -F "API_KEY" /configs        # literal substring (triggers full scan)`,
	Args:              cobra.RangeArgs(1, 2),
	ValidArgsFunction: completion.RemotePathCompletion,
	Run: func(cmd *cobra.Command, args []string) {
		pattern := args[0]
		searchPath := ""
		if len(args) > 1 {
			searchPath = args[1]
		}
		if searchPath != "" || grRegex || grFixed {
			grAllFiles = true
		}
		if grAllFiles {
			runGrepFileScan(pattern, searchPath)
			return
		}
		runGrepIndex(pattern)
	},
}

func init() {
	grCmd.Flags().BoolVarP(&grAllFiles, "all-files", "A", false, "scan every text file (slower, covers unindexed, enables -E/-F)")
	grCmd.Flags().BoolVarP(&grRecursive, "recursive", "r", false, "scan-mode: recurse into subdirectories")
	grCmd.Flags().BoolVarP(&grFilesOnly, "files-only", "l", false, "show only file names")
	grCmd.Flags().BoolVarP(&grIgnoreCase, "ignore-case", "i", false, "scan-mode: case-insensitive matching")
	grCmd.Flags().IntVarP(&grMaxResults, "max", "m", 200, "maximum number of matches to show")
	grCmd.Flags().BoolVarP(&grRegex, "regex", "E", false, "scan-mode: treat pattern as regex (implies -A)")
	grCmd.Flags().BoolVarP(&grFixed, "fixed", "F", false, "scan-mode: literal substring (implies -A)")
	grCmd.MarkFlagsMutuallyExclusive("regex", "fixed")
	rootCmd.AddCommand(grCmd)
}

func runGrepIndex(pattern string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	queryTokens := tokenizeGrQuery(pattern)
	if len(queryTokens) == 0 {
		output.PrintError(fmt.Sprintf("No searchable tokens in pattern (need %d+ chars, alphanumeric)", grMinTokenRunes))
		ExitWithError()
	}

	if !e2ee.EnsureNamesReadable() {
		return
	}

	matchCount := 0
	cursor := ""

	for {
		opts := map[string]string{}
		if cursor != "" {
			opts["cursor"] = cursor
		}
		opts["limit"] = "50"
		_, page := cmdutil.ExecuteCommand[api.GrIndexPayload](ctx, "gr", opts, ExitWithError)

		for _, item := range page.Items {
			if matchCount >= grMaxResults {
				break
			}
			payload, err := unsealGrItem(item.Payload)
			if err != nil {
				continue
			}
			matchedSnippets, matched := matchGrPayload(payload, queryTokens)
			if !matched {
				continue
			}
			name, err := decryptGrName(item.E2EEDisplayName)
			if err != nil || name == "" {
				name = "<encrypted:" + item.NodeID[:8] + ">"
			}
			printGrIndexHit(name, matchedSnippets)
			matchCount++
		}

		if matchCount >= grMaxResults {
			break
		}
		if page.Done || page.NextCursor == nil || *page.NextCursor == "" {
			break
		}
		cursor = *page.NextCursor
	}

	if !GetQuietOutput() {
		fmt.Fprintf(os.Stderr, "\n%d match(es)\n", matchCount)
	}
}

const grMinTokenRunes = 2

func tokenizeGrQuery(raw string) []string {
	out := []string{}
	seen := map[string]struct{}{}
	cur := strings.Builder{}
	flush := func() {
		s := strings.ToLower(cur.String())
		cur.Reset()
		if utf8.RuneCountInString(s) < grMinTokenRunes {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, r := range raw {
		if isGrWordChar(r) {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func isGrWordChar(r rune) bool {
	if r == '_' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
		return true
	}
	return r > 127
}

type grIndexContent struct {
	SchemaVersion int               `json:"schemaVersion"`
	Tokens        []string          `json:"tokens"`
	Snippets      map[string]string `json:"snippets"`
}

func unsealGrItem(sealedB64 string) (*grIndexContent, error) {
	sealed, err := base64.StdEncoding.DecodeString(sealedB64)
	if err != nil {
		return nil, err
	}
	_, priv := e2ee.GetKeyPair(ExitWithError)
	framed, err := crypto.HybridUnseal(sealed, priv)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := crypto.UnframeIndexBody(framed)
	if err != nil {
		return nil, err
	}
	var payload grIndexContent
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		return nil, err
	}
	return &payload, nil
}

func decryptGrName(sealedNameB64 string) (string, error) {
	if sealedNameB64 == "" {
		return "", nil
	}
	sealed, err := base64.StdEncoding.DecodeString(sealedNameB64)
	if err != nil {
		return "", err
	}
	_, priv := e2ee.GetKeyPair(ExitWithError)
	return crypto.UnsealDisplayName(sealed, priv)
}

func matchGrPayload(payload *grIndexContent, queryTokens []string) ([]string, bool) {
	if payload == nil {
		return nil, false
	}
	tokenSet := make(map[string]struct{}, len(payload.Tokens))
	for _, t := range payload.Tokens {
		tokenSet[t] = struct{}{}
	}
	snippets := []string{}
	for _, qt := range queryTokens {
		if _, ok := tokenSet[qt]; ok {
			if s, ok := payload.Snippets[qt]; ok && s != "" {
				snippets = append(snippets, s)
			}
			continue
		}
		var found string
		for _, t := range payload.Tokens {
			if strings.Contains(t, qt) {
				found = t
				break
			}
		}
		if found == "" {
			return nil, false
		}
		if s, ok := payload.Snippets[found]; ok && s != "" {
			snippets = append(snippets, s)
		}
	}
	return snippets, true
}

func printGrIndexHit(name string, snippets []string) {
	if grFilesOnly || len(snippets) == 0 {
		fmt.Println(color.CyanString(name))
		return
	}
	fmt.Println(color.CyanString(name))
	for _, s := range snippets {
		fmt.Printf("  %s\n", color.HiBlackString(s))
	}
}

func runGrepFileScan(pattern, searchPath string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	if !e2ee.EnsureNamesReadable() {
		return
	}

	resolvedPath := cmdutil.ResolvePath(searchPath)

	mode := cmdutil.MatchRegex
	if grFixed {
		mode = cmdutil.MatchFixed
	}
	matcher, err := cmdutil.CompileMatcher(pattern, mode, grIgnoreCase)
	if err != nil {
		output.PrintError("Invalid pattern: " + err.Error())
		ExitWithError()
	}

	type fileEntry struct {
		remotePath string
		name       string
	}
	var files []fileEntry

	if grRecursive {
		treeOpts := map[string]string{
			"source": resolvedPath,
			"depth":  "50",
		}
		e2ee.AddPathTokensFor(treeOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
		_, tree := cmdutil.ExecuteCommand[api.TreePayload](ctx, "tr", treeOpts, ExitWithError)
		decryptTreeEntries(tree.Entries)

		cmdutil.WalkTreeFiles(tree.Entries, resolvedPath, func(e api.TreeEntry, remotePath, relPath string) {
			if isGrepTarget(e.Name) {
				files = append(files, fileEntry{remotePath: remotePath, name: relPath})
			}
		})
	} else {
		lsOpts := map[string]string{"source": resolvedPath}
		e2ee.AddPathTokensFor(lsOpts, resolvedPath, e2ee.SelfOnly, ExitWithError)
		_, listing := cmdutil.ExecuteCommand[api.ListPayload](ctx, "ls", lsOpts, ExitWithError)

		for i := range listing.Entries {
			item := &listing.Entries[i]
			if item.E2EEDisplayName != "" {
				item.Name = e2ee.DecryptE2EEName(item.E2EEDisplayName)
			}
			if item.Type != "directory" && isGrepTarget(item.Name) {
				remotePath := resolvedPath
				if remotePath == "/" {
					remotePath = "/" + item.Name
				} else {
					remotePath = remotePath + "/" + item.Name
				}
				files = append(files, fileEntry{remotePath: remotePath, name: item.Name})
			}
		}
	}

	if len(files) == 0 {
		output.PrintInfo("No text files found in " + resolvedPath)
		return
	}

	if !GetQuietOutput() {
		fmt.Fprintf(os.Stderr, "Searching %d text file(s)...\n", len(files))
	}

	client := api.NewClient()
	matchCount := 0
	fileMatchCount := 0

	for _, f := range files {
		if matchCount >= grMaxResults && !grFilesOnly {
			break
		}

		perFileOpts := map[string]string{}
		e2ee.AddPathTokensFor(perFileOpts, f.remotePath, e2ee.SelfAndAncestors, ExitWithError)

		data, dlResult, err := client.DownloadToMemory(ctx, f.remotePath, perFileOpts)
		if err != nil {
			continue
		}
		if err := gateAndVerify(data, dlResult); err != nil {
			if !GetQuietOutput() {
				fmt.Fprintf(os.Stderr, "skip %s: %v\n", f.name, err)
			}
			continue
		}
		data = decryptToBytes(data, dlResult)
		if data == nil {
			continue
		}

		matches := grepBytes(data, matcher)

		if len(matches) > 0 {
			fileMatchCount++
			if grFilesOnly {
				fmt.Println(color.CyanString(f.name))
			} else {
				for _, m := range matches {
					if matchCount >= grMaxResults {
						break
					}
					fmt.Printf("%s%s%s\n",
						color.CyanString(f.name),
						color.HiBlackString(":%d:", m.lineNum),
						highlightMatch(m.line, matcher))
					matchCount++
				}
			}
		}
	}

	if !GetQuietOutput() {
		if grFilesOnly {
			fmt.Fprintf(os.Stderr, "\n%d file(s) matched\n", fileMatchCount)
		} else {
			fmt.Fprintf(os.Stderr, "\n%d match(es) in %d file(s)\n", matchCount, fileMatchCount)
		}
	}
}

type grepMatch struct {
	lineNum int
	line    string
}

func grepBytes(data []byte, m *cmdutil.Matcher) []grepMatch {
	var matches []grepMatch
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 256*1024), 256*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if m.MatchString(line) {
			matches = append(matches, grepMatch{lineNum: lineNum, line: line})
		}
	}
	return matches
}

func gateAndVerify(data []byte, dlResult *api.DownloadResult) error {
	if err := e2ee.RequireEncryptedDownload(dlResult); err != nil {
		return err
	}
	return e2ee.VerifyDownloadIntegrity(bytes.NewReader(data), dlResult)
}

func decryptToBytes(ciphertext []byte, dlResult *api.DownloadResult) []byte {
	_, privKey := e2ee.GetKeyPair(ExitWithError)
	sealedKeyBytes, err := base64.StdEncoding.DecodeString(dlResult.SealedKey)
	if err != nil {
		return nil
	}
	dataKey, err := crypto.UnsealDataKey(sealedKeyBytes, privKey)
	if err != nil {
		return nil
	}
	metaJSON, err := base64.StdEncoding.DecodeString(dlResult.EncryptionMeta)
	if err != nil {
		return nil
	}
	var meta crypto.EncryptionMetadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		return nil
	}
	plaintext, err := crypto.DecryptBytes(ciphertext, dataKey, &meta)
	if err != nil {
		return nil
	}
	return plaintext
}

func highlightMatch(line string, m *cmdutil.Matcher) string {
	if re := m.HighlightRegex(); re != nil {
		return re.ReplaceAllStringFunc(line, func(s string) string {
			return color.RedString(s)
		})
	}
	return line
}

func isGrepTarget(name string) bool {
	ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(name), "."))
	return filetypes.IsText(ext)
}
