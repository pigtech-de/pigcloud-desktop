package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

const phpCommandDir = "../../private/cli/commands"

var (
	phpName    = regexp.MustCompile(`getName\(\)\s*:\s*string\s*{\s*return\s*'([a-z0-9_]+)'`)
	phpAliases = regexp.MustCompile(`getAliases\(\)\s*:\s*array\s*{\s*return\s*\[([^\]]*)\]`)
	phpLiteral = regexp.MustCompile(`'([^']*)'`)
)

func serverCommandNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	err := filepath.WalkDir(filepath.FromSlash(phpCommandDir), func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), "Command.php") {
			return nil
		}
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		src := string(body)
		m := phpName.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("%s: no getName() returning a literal; the parser stopped matching", p)
			return nil
		}
		names[m[1]] = true
		if a := phpAliases.FindStringSubmatch(src); a != nil {
			for _, lit := range phpLiteral.FindAllStringSubmatch(a[1], -1) {
				if lit[1] != "" {
					names[lit[1]] = true
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", phpCommandDir, err)
	}
	if len(names) < 50 {
		t.Fatalf("parsed only %d server command names from %s; the PHP layout changed and this guard stopped guarding",
			len(names), phpCommandDir)
	}
	return names
}

func goCommandNames(t *testing.T) map[string]bool {
	t.Helper()
	names := map[string]bool{}
	for _, cmd := range rootCmd.Commands() {
		if cmd.Hidden {
			continue
		}
		names[cmd.Name()] = true
		for _, a := range cmd.Aliases {
			names[a] = true
		}
	}
	if len(names) < 50 {
		t.Fatalf("only %d cobra names found; the command tree stopped being enumerable", len(names))
	}
	return names
}

func TestFindLocalCommandCoversEveryGoOnlyCommand(t *testing.T) {
	server := serverCommandNames(t)

	var missing, stale []string
	for name := range goCommandNames(t) {
		local := findLocalCommand(name) != nil
		switch {
		case server[name] && local:
			stale = append(stale, name)
		case !server[name] && !local:
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)

	for _, name := range missing {
		t.Errorf("`pc hl %s` has no server counterpart and no clientOnly entry, so it asks the server and exits with Unknown command", name)
	}
	for _, name := range stale {
		t.Errorf("`pc hl %s` is answered locally even though the server documents it; the rich help is lost", name)
	}
}

func TestFindLocalCommandAnswersForTheGoOnlyDiagnosticCommands(t *testing.T) {
	server := serverCommandNames(t)
	for _, name := range []string{"dr", "doctor", "vf", "verify"} {
		if server[name] {
			t.Errorf("%q gained a PHP command class; it should fall through to the server help now", name)
			continue
		}
		if findLocalCommand(name) == nil {
			t.Errorf("`pc hl %s` falls through to the server, which has no such command", name)
		}
	}
}

func TestFindLocalCommandResolvesAliasesToTheSameCommand(t *testing.T) {
	pairs := [][2]string{
		{"li", "login"}, {"lo", "logout"}, {"lk", "lock"}, {"uk", "unlock"},
		{"cf", "config"}, {"cm", "completion"}, {"op", "open"}, {"sh", "shell"},
		{"vr", "version"}, {"mn", "mount"}, {"di", "diff"}, {"hi", "welcome"},
	}
	for _, p := range pairs {
		short, long := findLocalCommand(p[0]), findLocalCommand(p[1])
		if short == nil {
			t.Errorf("findLocalCommand(%q) = nil", p[0])
			continue
		}
		if long == nil {
			t.Errorf("findLocalCommand(%q) = nil; the alias must reach the same command", p[1])
			continue
		}
		if short != long {
			t.Errorf("%q and %q resolve to different commands (%s vs %s)", p[0], p[1], short.Name(), long.Name())
		}
	}
}

func TestFindLocalCommandRejectsUnknownNames(t *testing.T) {
	for _, name := range []string{"", "definitely-not-a-command", "LI", "Login", " li"} {
		if got := findLocalCommand(name); got != nil {
			t.Errorf("findLocalCommand(%q) = %s, want nil", name, got.Name())
		}
	}
}

func TestFindLocalCommandListsNothingCobraDoesNotRegister(t *testing.T) {
	goNames := goCommandNames(t)
	for _, name := range []string{
		"li", "login", "lo", "logout", "lk", "lock", "uk", "unlock",
		"cf", "config", "cm", "completion", "op", "open", "sh", "shell",
		"vr", "version", "mn", "mount", "di", "diff", "hi", "welcome",
	} {
		if !goNames[name] {
			t.Errorf("clientOnly lists %q, which cobra no longer registers", name)
		}
		if findLocalCommand(name) == nil {
			t.Errorf("findLocalCommand(%q) = nil despite the clientOnly entry", name)
		}
	}
}

func TestVisibleSubcommandsHidesHiddenOnes(t *testing.T) {
	parent := &cobra.Command{Use: "parent"}
	shown := &cobra.Command{Use: "shown"}
	hidden := &cobra.Command{Use: "hidden", Hidden: true}
	parent.AddCommand(shown, hidden)

	got := visibleSubcommands(parent)
	if len(got) != 1 || got[0].Name() != "shown" {
		names := make([]string, 0, len(got))
		for _, c := range got {
			names = append(names, c.Name())
		}
		t.Fatalf("visibleSubcommands = %v, want [shown]", names)
	}
	if got := visibleSubcommands(&cobra.Command{Use: "leaf"}); len(got) != 0 {
		t.Errorf("a leaf command has no subcommands, got %d", len(got))
	}
}

func TestVisibleSubcommandsMatchesTheRegisteredTree(t *testing.T) {
	var mn *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "mn" {
			mn = cmd
			break
		}
	}
	if mn == nil {
		t.Fatal("mn is no longer registered")
	}

	want := 0
	for _, sub := range mn.Commands() {
		if !sub.Hidden {
			want++
		}
	}
	if want < 5 {
		t.Fatalf("mn exposes only %d visible subcommands; the walk broke", want)
	}
	if got := len(visibleSubcommands(mn)); got != want {
		t.Errorf("visibleSubcommands(mn) = %d, want %d", got, want)
	}
}

func TestBuildFlagHintsPrefersShorthandsAndSkipsHelp(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	cmd.Flags().BoolP("all", "a", false, "")
	cmd.Flags().String("skip-existing", "", "")
	cmd.Flags().BoolP("secret", "s", false, "")
	if err := cmd.Flags().MarkHidden("secret"); err != nil {
		t.Fatalf("mark hidden: %v", err)
	}
	cmd.InitDefaultHelpFlag()

	got := buildFlagHints(cmd)
	if !strings.Contains(got, "[-a]") {
		t.Errorf("hints = %q, want the -a shorthand", got)
	}
	if !strings.Contains(got, "[--skip-existing]") {
		t.Errorf("hints = %q, a shorthand-less flag must fall back to its long name", got)
	}
	if strings.Contains(got, "[--all]") {
		t.Errorf("hints = %q, a flag with a shorthand must not also print its long name", got)
	}
	if strings.Contains(got, "secret") {
		t.Errorf("hints = %q, hidden flags must stay out of the usage line", got)
	}
	if strings.Contains(got, "help") || strings.Contains(got, "[-h]") {
		t.Errorf("hints = %q, --help must be filtered", got)
	}
}

func TestBuildFlagHintsIsEmptyForAFlaglessCommand(t *testing.T) {
	cmd := &cobra.Command{Use: "x"}
	cmd.InitDefaultHelpFlag()
	if got := buildFlagHints(cmd); got != "" {
		t.Errorf("buildFlagHints = %q, want empty", got)
	}
}

func TestBuildFlagHintsCoversEveryVisibleLocalFlag(t *testing.T) {
	var ls *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "ls" {
			ls = cmd
			break
		}
	}
	if ls == nil {
		t.Fatal("ls is no longer registered")
	}

	got := buildFlagHints(ls)
	checked := 0
	ls.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if f.Hidden || f.Name == "help" {
			return
		}
		checked++
		token := "[--" + f.Name + "]"
		if f.Shorthand != "" {
			token = "[-" + f.Shorthand + "]"
		}
		if !strings.Contains(got, token) {
			t.Errorf("%s missing from %q", token, got)
		}
	})
	if checked < 5 {
		t.Fatalf("only %d flags walked on ls; the check is near-vacuous", checked)
	}
}
