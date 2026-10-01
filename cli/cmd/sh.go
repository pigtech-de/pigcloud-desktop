package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"pigcloud/internal/completion"
	"pigcloud/internal/config"
	"pigcloud/internal/output"

	"github.com/chzyer/readline"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const (
	shellHistoryLimit    = 500
	shellInputBufferSize = 4096
)

var shellCmd = &cobra.Command{
	Use:     "sh",
	GroupID: GroupTools,
	Aliases: []string{"shell"},
	Short:   "Start an interactive shell",
	Long: `Start an interactive shell for running multiple commands.

The shell shows your current working directory in the prompt.
Type 'exit' or 'quit' to leave the shell.
Press Ctrl+C to cancel the current line, Ctrl+D to exit.

Example session:
  / > ls
  / > cd Documents
  /Documents > ct readme.txt
  /Documents > exit`,
	Run: func(cmd *cobra.Command, args []string) {
		runShell()
	},
}

func init() {
	rootCmd.AddCommand(shellCmd)
}

func runShell() {
	if !config.IsLoggedIn() {
		output.PrintError("Not logged in. Run 'pigcloud login' first.")
		os.Exit(1)
	}

	SetShellMode(true)
	defer SetShellMode(false)

	fmt.Println(color.CyanString("PigCloud Interactive Shell"))
	fmt.Println("Type 'exit' or 'quit' to leave, 'help' for commands")
	fmt.Println()

	completer := &shellCompleter{}

	histPath := historyFilePath()
	if _, err := os.Stat(histPath); os.IsNotExist(err) {
		if f, err := os.OpenFile(histPath, os.O_CREATE|os.O_WRONLY, 0600); err == nil {
			f.Close()
		}
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            buildPrompt(),
		HistoryFile:       histPath,
		HistoryLimit:      shellHistoryLimit,
		AutoComplete:      completer,
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		output.PrintWarning("Readline unavailable, falling back to basic mode")
		runShellBasic()
		return
	}
	defer rl.Close()

	for {
		rl.SetPrompt(buildPrompt())

		line, err := rl.Readline()
		if err == readline.ErrInterrupt {
			continue
		}
		if err == io.EOF {
			fmt.Println("Goodbye!")
			break
		}
		if err != nil {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		args := parseCommandLine(line)
		if len(args) == 0 {
			continue
		}

		executeShellCommand(args)
	}
}

func runShellBasic() {
	scanner := readline.NewCancelableStdin(os.Stdin)
	defer scanner.Close()
	buf := make([]byte, shellInputBufferSize)

	for {
		cwd := config.GetCwd()
		fmt.Print(color.GreenString(cwd) + " > ")

		n, err := scanner.Read(buf)
		if err != nil {
			fmt.Println()
			break
		}

		line := strings.TrimSpace(string(buf[:n]))
		if line == "" {
			continue
		}

		if line == "exit" || line == "quit" {
			fmt.Println("Goodbye!")
			break
		}

		args := parseCommandLine(line)
		if len(args) == 0 {
			continue
		}

		executeShellCommand(args)
	}
}

func buildPrompt() string {
	cwd := config.GetCwd()
	return color.GreenString(cwd) + " > "
}

func historyFilePath() string {
	configPath := config.GetConfigPath()
	return filepath.Join(filepath.Dir(configPath), "shell_history")
}

type shellCompleter struct{}

func (c *shellCompleter) Do(line []rune, pos int) (newLine [][]rune, length int) {
	lineStr := string(line[:pos])
	parts := strings.Fields(lineStr)

	if len(parts) == 0 || (len(parts) == 1 && !strings.HasSuffix(lineStr, " ")) {
		prefix := ""
		if len(parts) == 1 {
			prefix = parts[0]
		}
		return c.completeCommand(prefix)
	}

	lastArg := ""
	if !strings.HasSuffix(lineStr, " ") {
		lastArg = parts[len(parts)-1]
	}

	if strings.HasPrefix(lastArg, "-") {
		return c.completeFlags(parts[0], lastArg)
	}

	return c.completePath(lastArg)
}

func (c *shellCompleter) completeCommand(prefix string) ([][]rune, int) {
	var candidates [][]rune
	for _, cmd := range rootCmd.Commands() {
		if !cmd.IsAvailableCommand() {
			continue
		}
		name := cmd.Name()
		if strings.HasPrefix(name, prefix) {
			suffix := name[len(prefix):]
			candidates = append(candidates, []rune(suffix+" "))
		}
		for _, alias := range cmd.Aliases {
			if strings.HasPrefix(alias, prefix) {
				suffix := alias[len(prefix):]
				candidates = append(candidates, []rune(suffix+" "))
			}
		}
	}
	return candidates, len(prefix)
}

func (c *shellCompleter) completeFlags(cmdName, prefix string) ([][]rune, int) {
	var target *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == cmdName {
			target = cmd
			break
		}
		if slices.Contains(cmd.Aliases, cmdName) {
			target = cmd
		}
		if target != nil {
			break
		}
	}
	if target == nil {
		return nil, 0
	}

	seen := map[string]struct{}{}
	var tokens []string
	add := func(token string) {
		if !strings.HasPrefix(token, prefix) {
			return
		}
		if _, dup := seen[token]; dup {
			return
		}
		seen[token] = struct{}{}
		tokens = append(tokens, token)
	}
	collect := func(f *pflag.Flag) {
		if f.Hidden {
			return
		}
		add("--" + f.Name)
		if f.Shorthand != "" {
			add("-" + f.Shorthand)
		}
	}
	target.Flags().VisitAll(collect)
	target.InheritedFlags().VisitAll(collect)
	sort.Strings(tokens)

	candidates := make([][]rune, 0, len(tokens))
	for _, token := range tokens {
		candidates = append(candidates, []rune(token[len(prefix):]+" "))
	}
	return candidates, len(prefix)
}

func (c *shellCompleter) completePath(toComplete string) ([][]rune, int) {
	completions, _ := completion.RemotePathCompletion(nil, nil, toComplete)
	if len(completions) == 0 {
		return nil, 0
	}

	var candidates [][]rune
	for _, comp := range completions {
		if idx := strings.Index(comp, "\t"); idx >= 0 {
			comp = comp[:idx]
		}
		suffix := comp
		if len(toComplete) > 0 {
			if strings.HasPrefix(comp, toComplete) {
				suffix = comp[len(toComplete):]
			}
		}
		candidates = append(candidates, []rune(suffix))
	}
	return candidates, len(toComplete)
}

func parseCommandLine(line string) []string {
	var args []string
	var current strings.Builder
	inQuote := false
	quoteChar := rune(0)

	for _, r := range line {
		switch {
		case r == '"' || r == '\'':
			if inQuote && r == quoteChar {
				inQuote = false
				quoteChar = 0
			} else if !inQuote {
				inQuote = true
				quoteChar = r
			} else {
				current.WriteRune(r)
			}
		case r == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}

	if current.Len() > 0 {
		args = append(args, current.String())
	}

	return args
}

func executeShellCommand(args []string) {
	defer func() {
		if r := recover(); r != nil {
			if r != "command_error" {
				panic(r)
			}
		}
	}()

	rootCmd.SetArgs(args)

	if err := rootCmd.Execute(); err != nil {
	}
}
