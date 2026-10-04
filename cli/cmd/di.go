package cmd

import (
	"bufio"
	"fmt"
	"maps"
	"os"
	"strconv"
	"strings"

	"pigcloud/internal/api"
	"pigcloud/internal/cmdutil"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/output"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var diLocal string

var diCmd = &cobra.Command{
	Use:     "di <file> [version-a] [version-b]",
	GroupID: GroupFiles,
	Aliases: []string{"diff"},
	Short:   "Diff a file between versions",
	Long: `Show differences between two versions of a file, between a version
and the current file, or between the cloud file and a local copy (--local).

Only works with text files. Downloads and decrypts the cloud side locally,
then displays a unified diff.`,
	Example: `pc di /report.md 3 5               # Diff version 3 vs version 5
pc di /report.md 3                 # Diff version 3 vs current
pc di /report.md -l ./report.md    # Diff cloud file vs local copy
pc di /report.md 3 -l ./report.md  # Diff version 3 vs local copy`,
	Args: func(cmd *cobra.Command, args []string) error {
		if diLocal != "" {
			if len(args) < 1 || len(args) > 2 {
				return fmt.Errorf("accepts 1 or 2 args with --local, received %d", len(args))
			}
			return nil
		}
		if len(args) < 2 || len(args) > 3 {
			return fmt.Errorf("accepts 2 or 3 args, received %d", len(args))
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		filePath := args[0]
		versionA := ""
		if len(args) > 1 {
			versionA = args[1]
		}
		versionB := ""
		if len(args) > 2 {
			versionB = args[2]
		}
		runDiff(filePath, versionA, versionB)
	},
}

func init() {
	diCmd.Flags().StringVarP(&diLocal, "local", "l", "", "compare against a local file instead of a second version")
	rootCmd.AddCommand(diCmd)
}

func runDiff(filePath, versionA, versionB string) {
	ctx, cancel := cmdutil.StartAuthed(ExitWithError)
	defer cancel()

	resolvedPath := cmdutil.ResolvePath(filePath)

	pathOpts := map[string]string{}
	cmdutil.AddPathTokensFor(pathOpts, resolvedPath, e2ee.SelfAndParent, ExitWithError)

	displayA, displayB := versionA, versionB
	if versionA != "" || versionB != "" {
		listOpts := map[string]string{"source": resolvedPath, "mode": "list"}
		maps.Copy(listOpts, pathOpts)
		_, versionList := cmdutil.ExecuteCommand[api.VersionListPayload](ctx, "vh", listOpts, ExitWithError)
		versionA = resolveVersionArg(versionList.Versions, versionA, resolvedPath)
		versionB = resolveVersionArg(versionList.Versions, versionB, resolvedPath)
	}

	client := api.NewClient()

	var tempPaths []string
	defer func() {
		for _, p := range tempPaths {
			os.Remove(p)
		}
	}()

	fetchCloudLines := func(version, label string) []string {
		tmp, err := os.CreateTemp("", "pigcloud-diff-*")
		if err != nil {
			output.PrintError("Failed to create temp file: " + err.Error())
			ExitWithError()
		}
		tmpPath := tmp.Name()
		tmp.Close()
		tempPaths = append(tempPaths, tmpPath)

		var dlResult *api.DownloadResult
		if version == "" {
			dlResult, err = client.Download(ctx, resolvedPath, tmpPath, nil, pathOpts)
		} else {
			opts := map[string]string{
				"source":     resolvedPath,
				"mode":       "download",
				"version-id": version,
			}
			maps.Copy(opts, pathOpts)
			dlResult, err = client.DownloadCommand(ctx, "vh", opts, tmpPath, nil)
		}
		if err != nil {
			output.PrintError("Failed to download " + label + ": " + err.Error())
			ExitWithError()
		}
		decryptDownloadedFile(tmpPath, dlResult)
		lines, err := readLines(tmpPath)
		if err != nil {
			output.PrintError("Failed to read " + label + ": " + err.Error())
			ExitWithError()
		}
		return lines
	}

	labelA := "cloud"
	if versionA != "" {
		labelA = "v" + strings.TrimPrefix(strings.ToLower(displayA), "v")
	}
	linesA := fetchCloudLines(versionA, labelA)

	var linesB []string
	labelB := "current"
	pathB := resolvedPath
	if diLocal != "" {
		labelB = "local"
		pathB = diLocal
		var err error
		linesB, err = readLines(diLocal)
		if err != nil {
			output.PrintError("Failed to read local file: " + err.Error())
			ExitWithError()
		}
	} else if versionB != "" {
		labelB = "v" + strings.TrimPrefix(strings.ToLower(displayB), "v")
		linesB = fetchCloudLines(versionB, labelB)
	} else {
		linesB = fetchCloudLines("", "current file")
	}

	diffs := simpleDiff(linesA, linesB)
	if len(diffs) == 0 {
		output.PrintInfo("No differences")
		return
	}

	fmt.Printf("--- %s %s\n", resolvedPath, labelA)
	fmt.Printf("+++ %s %s\n", pathB, labelB)

	for _, d := range diffs {
		switch d.op {
		case diffEqual:
			fmt.Printf(" %s\n", d.line)
		case diffRemove:
			fmt.Println(color.RedString("-%s", d.line))
		case diffAdd:
			fmt.Println(color.GreenString("+%s", d.line))
		}
	}
}

func resolveVersionArg(versions []api.VersionEntry, arg, filePath string) string {
	if arg == "" {
		return ""
	}
	n, err := strconv.Atoi(strings.TrimPrefix(strings.ToLower(arg), "v"))
	if err != nil {
		output.PrintError("Invalid version: " + arg)
		ExitWithError()
	}
	for _, v := range versions {
		if v.VersionNumber == n {
			return strconv.Itoa(v.ID)
		}
	}
	for _, v := range versions {
		if v.ID == n {
			return strconv.Itoa(n)
		}
	}
	output.PrintError(fmt.Sprintf("Version %s not found for %s (%d version(s), see pc vh)", arg, filePath, len(versions)))
	ExitWithError()
	return ""
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

const (
	diffEqual  = 0
	diffAdd    = 1
	diffRemove = 2
)

type diffLine struct {
	op   int
	line string
}

func simpleDiff(a, b []string) []diffLine {
	n, m := len(a), len(b)

	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}

	var all []diffLine
	i, j := 0, 0
	for i < n || j < m {
		if i < n && j < m && a[i] == b[j] {
			all = append(all, diffLine{diffEqual, a[i]})
			i++
			j++
		} else if j < m && (i >= n || lcs[i][j+1] >= lcs[i+1][j]) {
			all = append(all, diffLine{diffAdd, b[j]})
			j++
		} else {
			all = append(all, diffLine{diffRemove, a[i]})
			i++
		}
	}

	const contextLines = 3
	show := make([]bool, len(all))
	for idx, d := range all {
		if d.op != diffEqual {
			for c := max(0, idx-contextLines); c <= min(len(all)-1, idx+contextLines); c++ {
				show[c] = true
			}
		}
	}

	var result []diffLine
	for idx, d := range all {
		if show[idx] {
			result = append(result, d)
		}
	}
	return result
}
