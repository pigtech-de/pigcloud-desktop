package cmd

import (
	"bytes"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

func TestParseCommandLineRespectsQuoting(t *testing.T) {
	cases := []struct {
		name string
		line string
		want []string
	}{
		{"plain words", "ls /Photos", []string{"ls", "/Photos"}},
		{"collapses runs of spaces", "ls    /Photos", []string{"ls", "/Photos"}},
		{"leading and trailing spaces", "  ls /Photos  ", []string{"ls", "/Photos"}},
		{"double-quoted name with spaces", `rm "my file.txt"`, []string{"rm", "my file.txt"}},
		{"single-quoted name with spaces", `rm 'my file.txt'`, []string{"rm", "my file.txt"}},
		{"quote inside the other quote survives", `ct "it's here.txt"`, []string{"ct", "it's here.txt"}},
		{"double quote inside single quotes", `ct 'say "hi".txt'`, []string{"ct", `say "hi".txt`}},
		{"quotes glued to a word", `mv a"b c"d`, []string{"mv", "ab cd"}},
		{"flags pass through", "ls -a -n 5", []string{"ls", "-a", "-n", "5"}},
		{"empty line", "", nil},
		{"spaces only", "     ", nil},
		{"quoted empty string is dropped", `ct ""`, []string{"ct"}},
		{"unterminated quote takes the rest", `rm "no end`, []string{"rm", "no end"}},
		{"unicode name", `ct "Prüfung Datei.txt"`, []string{"ct", "Prüfung Datei.txt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := parseCommandLine(tc.line)
			if len(got) != len(tc.want) {
				t.Fatalf("parseCommandLine(%q) = %#v, want %#v", tc.line, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("arg %d = %q, want %q (full: %#v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestParseCommandLineConservesContentOverRandomLines(t *testing.T) {
	alphabet := []rune(`ab -/. "' `)
	for range 200 {
		var sb strings.Builder
		for i := 0; i < randInt(t, 24); i++ {
			sb.WriteRune(alphabet[randInt(t, len(alphabet))])
		}
		line := sb.String()
		args := parseCommandLine(line)

		for _, arg := range args {
			if arg == "" {
				t.Fatalf("line %q produced an empty argument", line)
			}
		}

		joined := strings.Join(args, "")
		src := 0
		for _, r := range line {
			if r == '"' || r == '\'' || r == ' ' {
				continue
			}
			idx := strings.IndexRune(joined[src:], r)
			if idx < 0 {
				t.Fatalf("line %q dropped or reordered %q; args %#v", line, string(r), args)
			}
			src += idx + len(string(r))
		}

		again := parseCommandLine(line)
		if strings.Join(again, "\x00") != strings.Join(args, "\x00") {
			t.Fatalf("line %q parsed differently on a second call: %#v then %#v", line, args, again)
		}
	}
}

func runesToStrings(in [][]rune) []string {
	out := make([]string, 0, len(in))
	for _, r := range in {
		out = append(out, string(r))
	}
	return out
}

func TestCompleteCommandEmitsTheMissingSuffixOnly(t *testing.T) {
	c := &shellCompleter{}
	got, length := c.completeCommand("ls")
	if length != 2 {
		t.Errorf("replacement length = %d, want len(prefix)=2", length)
	}
	strs := runesToStrings(got)
	if len(strs) == 0 {
		t.Fatal("no candidate for the ls command")
	}
	for _, s := range strs {
		if !strings.HasSuffix(s, " ") {
			t.Errorf("candidate %q must end in a space so the next token starts clean", s)
		}
	}
	if strs[0] != " " {
		t.Errorf("exact-match candidate = %q, want just the trailing space", strs[0])
	}
}

func TestCompleteCommandCoversEveryRegisteredNameAndAlias(t *testing.T) {
	c := &shellCompleter{}
	checked := 0
	for _, cmd := range rootCmd.Commands() {
		if !cmd.IsAvailableCommand() {
			continue
		}
		names := append([]string{cmd.Name()}, cmd.Aliases...)
		for _, name := range names {
			cands, _ := c.completeCommand(name)
			found := slices.Contains(runesToStrings(cands), " ")
			if !found {
				t.Errorf("%q completes to %v, never to itself", name, runesToStrings(cands))
			}
			checked++
		}
	}
	if checked < 40 {
		t.Fatalf("only %d names walked; the command tree stopped being enumerable", checked)
	}
}

func TestCompleteCommandEmptyPrefixOffersEverything(t *testing.T) {
	c := &shellCompleter{}
	got, length := c.completeCommand("")
	if length != 0 {
		t.Errorf("replacement length = %d, want 0", length)
	}
	visible := 0
	for _, cmd := range rootCmd.Commands() {
		if cmd.IsAvailableCommand() {
			visible += 1 + len(cmd.Aliases)
		}
	}
	if len(got) != visible {
		t.Errorf("offered %d candidates, %d names are available", len(got), visible)
	}
}

func TestCompleteCommandSkipsHiddenCommands(t *testing.T) {
	c := &shellCompleter{}
	hidden := 0
	for _, cmd := range rootCmd.Commands() {
		if !cmd.IsAvailableCommand() {
			hidden++
			cands, _ := c.completeCommand(cmd.Name())
			for _, s := range runesToStrings(cands) {
				if s == " " {
					t.Errorf("hidden command %q is offered by tab-completion", cmd.Name())
				}
			}
		}
	}
	if hidden == 0 {
		t.Skip("no hidden commands registered")
	}
}

func TestCompleteFlagsResolvesCommandsByAlias(t *testing.T) {
	c := &shellCompleter{}
	byName, _ := c.completeFlags("ls", "--")
	byAlias, _ := c.completeFlags("list", "--")
	if len(byName) == 0 {
		t.Fatal("ls offers no flags")
	}
	if len(byAlias) != len(byName) {
		t.Errorf("alias `list` offered %d flags, canonical `ls` offered %d", len(byAlias), len(byName))
	}

	got, length := c.completeFlags("definitely-not-a-command", "--")
	if got != nil || length != 0 {
		t.Errorf("an unknown command must offer nothing, got %v/%d", runesToStrings(got), length)
	}
}

func TestCompleteFlagsOffersEveryVisibleLocalAndGlobalFlag(t *testing.T) {
	var target = rootCmd
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == "ls" {
			target = cmd
			break
		}
	}
	if target == rootCmd {
		t.Fatal("ls is no longer registered")
	}

	want := map[string]bool{}
	target.Flags().VisitAll(func(f *pflag.Flag) {
		if !f.Hidden {
			want["--"+f.Name] = true
		}
	})
	target.InheritedFlags().VisitAll(func(f *pflag.Flag) {
		if !f.Hidden {
			want["--"+f.Name] = true
		}
	})
	if len(want) < 4 {
		t.Fatalf("only %d flags discovered on ls; the walk stopped working", len(want))
	}

	c := &shellCompleter{}
	cands, length := c.completeFlags("ls", "--")
	if length != 2 {
		t.Errorf("replacement length = %d, want len(\"--\")=2", length)
	}
	got := map[string]bool{}
	for _, s := range runesToStrings(cands) {
		got["--"+strings.TrimSpace(s)] = true
	}
	for flag := range want {
		if !got[flag] {
			t.Errorf("%s is not offered; completion set: %v", flag, runesToStrings(cands))
		}
	}
	if !got["--json"] {
		t.Errorf("global --json missing; inherited flags are not being walked: %v", runesToStrings(cands))
	}
}

func TestCompleteFlagsSkipsHiddenFlags(t *testing.T) {
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
	f := ls.Flags().Lookup("long")
	if f == nil {
		t.Fatal("ls --long is gone; pick another local flag to hide")
	}

	c := &shellCompleter{}
	before := runesToStrings(firstOf(c.completeFlags("ls", "--")))
	if !containsToken(before, "long") {
		t.Fatalf("--long is not offered even when visible: %v", before)
	}

	f.Hidden = true
	t.Cleanup(func() { f.Hidden = false })

	after := runesToStrings(firstOf(c.completeFlags("ls", "--")))
	if containsToken(after, "long") {
		t.Errorf("hidden --long is still offered: %v", after)
	}
	if len(after) != len(before)-1 {
		t.Errorf("hiding one flag changed the count by %d, want 1", len(before)-len(after))
	}
}

func containsToken(candidates []string, token string) bool {
	for _, s := range candidates {
		if strings.TrimSpace(s) == token {
			return true
		}
	}
	return false
}

func TestCompleteFlagsOffersShorthandsForSingleDash(t *testing.T) {
	c := &shellCompleter{}
	strs := runesToStrings(firstOf(c.completeFlags("ls", "-")))

	sawShort := false
	for _, s := range strs {
		if !strings.HasPrefix(s, "-") {
			sawShort = true
		}
	}
	if !sawShort {
		t.Errorf("no single-dash shorthand offered for `ls -`: %v", strs)
	}
	found := false
	for _, s := range strs {
		if strings.TrimSpace(s) == "a" {
			found = true
		}
	}
	if !found {
		t.Errorf("ls -a is not offered: %v", strs)
	}
}

func TestCompleteFlagsIsIdempotentAcrossRepeatedCalls(t *testing.T) {
	c := &shellCompleter{}
	for _, prefix := range []string{"--", "-", "--j"} {
		var first []string
		for call := 1; call <= 4; call++ {
			got := runesToStrings(firstOf(c.completeFlags("ls", prefix)))
			if call == 1 {
				first = got
				continue
			}
			if strings.Join(got, "\x00") != strings.Join(first, "\x00") {
				t.Fatalf("prefix %q: call %d returned %v, call 1 returned %v", prefix, call, got, first)
			}
		}

		counts := map[string]int{}
		for _, s := range first {
			counts[strings.TrimSpace(s)]++
		}
		for token, n := range counts {
			if n != 1 {
				t.Errorf("prefix %q: %q offered %d times, want exactly 1 (full: %v)", prefix, token, n, first)
			}
		}
	}
}

const coldStartHelperEnv = "PIGCLOUD_COMPLETE_FLAGS_COLD"

func TestCompleteFlagsOffersGlobalsOnTheVeryFirstCall(t *testing.T) {
	if os.Getenv(coldStartHelperEnv) == "1" {
		c := &shellCompleter{}
		cands := runesToStrings(firstOf(c.completeFlags("ls", "--")))

		got := map[string]bool{}
		for _, s := range cands {
			got[strings.TrimSpace(s)] = true
		}
		for _, global := range []string{"json", "quiet", "no-color", "config"} {
			if !got[global] {
				t.Errorf("--%s missing from the first completion of a session; the inherited-flag walk is gone", global)
			}
		}
		if !got["all"] {
			t.Error("command-local --all missing from the first completion")
		}

		sorted := append([]string(nil), cands...)
		sort.Strings(sorted)
		for i := range sorted {
			if sorted[i] != cands[i] {
				t.Fatalf("first completion is not sorted: %v", cands)
			}
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^"+t.Name()+"$", "-test.v")
	cmd.Env = append(os.Environ(), coldStartHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cold-start child failed: %v\n%s", err, out)
	}
	if !bytes.Contains(out, []byte("PASS")) {
		t.Fatalf("cold-start child did not report PASS:\n%s", out)
	}
}

func TestCompleteFlagsReturnsCandidatesInStableSortedOrder(t *testing.T) {
	c := &shellCompleter{}
	got := runesToStrings(firstOf(c.completeFlags("ls", "--")))
	if len(got) < 5 {
		t.Fatalf("only %d candidates; the check is near-vacuous", len(got))
	}
	sorted := append([]string(nil), got...)
	sort.Strings(sorted)
	for i := range sorted {
		if sorted[i] != got[i] {
			t.Fatalf("candidates are not sorted: got %v", got)
		}
	}
}

func firstOf(c [][]rune, _ int) [][]rune { return c }

func TestCompleterDoRoutesByTokenShape(t *testing.T) {
	c := &shellCompleter{}

	line := []rune("l")
	cands, length := c.Do(line, len(line))
	if length != 1 {
		t.Errorf("first-word completion replaced %d chars, want 1", length)
	}
	if len(cands) == 0 {
		t.Error("a bare first word must complete command names")
	}

	line = []rune("ls --")
	cands, length = c.Do(line, len(line))
	if length != 2 {
		t.Errorf("flag completion replaced %d chars, want 2", length)
	}
	if len(cands) == 0 {
		t.Error("a dash token must complete flags")
	}

	line = []rune("ls ")
	_, length = c.Do(line, len(line))
	if length != 0 {
		t.Errorf("a fresh empty token must replace 0 chars, got %d", length)
	}

	full := []rune("ls --json")
	_, length = c.Do(full, 4)
	if length != 1 {
		t.Errorf("cursor at 4 should complete the 1-char token \"-\", replaced %d", length)
	}
}

func TestCompleterDoOnAnEmptyLineOffersCommands(t *testing.T) {
	c := &shellCompleter{}
	cands, length := c.Do(nil, 0)
	if length != 0 {
		t.Errorf("empty line replaced %d chars, want 0", length)
	}
	if len(cands) == 0 {
		t.Error("an empty line must offer the command list")
	}
}
