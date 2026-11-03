package cmd

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
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
