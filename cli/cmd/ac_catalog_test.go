package cmd

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const notifierCatalogPath = "../../private/notify/Notifier.php"

type catalogEvent struct {
	key      string
	cliLabel string
	alerts   bool
}

var (
	ansiEscape   = regexp.MustCompile("\x1b\\[[0-9;]*m")
	phpString    = regexp.MustCompile(`'(?:[^'\\]|\\.)*'`)
	catalogEntry = regexp.MustCompile(`^'([a-z0-9_]+)' => \[$`)
	catalogCLI   = regexp.MustCompile(`^'cli' => '((?:[^'\\]|\\.)*)',$`)
	catalogAlert = regexp.MustCompile(`^'alert' => (null|\[)`)
)

func stripANSI(s string) string { return ansiEscape.ReplaceAllString(s, "") }

func parseNotifierCatalog(t *testing.T) []catalogEvent {
	t.Helper()
	raw, err := os.ReadFile(filepath.FromSlash(notifierCatalogPath))
	if err != nil {
		t.Fatalf("read %s: %v", notifierCatalogPath, err)
	}
	lines := strings.Split(string(raw), "\n")

	start := -1
	for i, line := range lines {
		if strings.Contains(line, "const array CATALOG = [") {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: no CATALOG declaration found", notifierCatalogPath)
	}

	var events []catalogEvent
	var cur *catalogEvent
	inChannels := false
	depth := 1

	for _, line := range lines[start+1:] {
		trimmed := strings.TrimSpace(line)
		blanked := phpString.ReplaceAllString(trimmed, "''")

		switch {
		case depth == 1:
			if m := catalogEntry.FindStringSubmatch(trimmed); m != nil {
				events = append(events, catalogEvent{key: m[1]})
				cur = &events[len(events)-1]
				inChannels = false
			}
		case depth == 2 && cur != nil:
			inChannels = false
			if m := catalogCLI.FindStringSubmatch(trimmed); m != nil {
				cur.cliLabel = m[1]
			}
			if strings.HasPrefix(trimmed, "'channels' => [") {
				inChannels = true
			}
		case depth == 3 && cur != nil && inChannels:
			if m := catalogAlert.FindStringSubmatch(trimmed); m != nil {
				cur.alerts = m[1] != "null"
			}
		}

		depth += strings.Count(blanked, "[") - strings.Count(blanked, "]")
		if depth <= 0 {
			break
		}
	}
	return events
}

func formatEventTypeCases(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "ac.go", nil, 0)
	if err != nil {
		t.Fatalf("parse ac.go: %v", err)
	}

	var cases []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "formatEventType" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			clause, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range clause.List {
				lit, ok := expr.(*ast.BasicLit)
				if ok && lit.Kind == token.STRING {
					cases = append(cases, strings.Trim(lit.Value, `"`))
				}
			}
			return true
		})
	}
	if len(cases) == 0 {
		t.Fatal("no switch cases found in formatEventType; the AST walk stopped matching")
	}
	return cases
}

func TestActivityLabelsCoverEveryAlertChannelEvent(t *testing.T) {
	events := parseNotifierCatalog(t)

	if len(events) < 40 {
		t.Fatalf("parsed only %d catalog entries from %s; the PHP layout changed and this guard stopped guarding",
			len(events), notifierCatalogPath)
	}
	alerting := 0
	for _, e := range events {
		if e.alerts {
			alerting++
		}
	}
	if alerting < 30 {
		t.Fatalf("parsed only %d alert-channel entries out of %d; the channels block layout changed",
			alerting, len(events))
	}

	for _, e := range events {
		if !e.alerts {
			continue
		}
		if e.cliLabel == "" {
			t.Errorf("%s: alert-channel event carries no 'cli' label in the catalog", e.key)
			continue
		}
		got := stripANSI(formatEventType(e.key))
		if got == e.key {
			t.Errorf("%s: formatEventType has no case, so `pc ac` prints the raw key instead of %q", e.key, e.cliLabel)
			continue
		}
		if got != e.cliLabel {
			t.Errorf("%s: formatEventType renders %q, catalog 'cli' says %q", e.key, got, e.cliLabel)
		}
	}
}

func TestActivityLabelsHaveNoCasesForRetiredEvents(t *testing.T) {
	known := map[string]bool{}
	for _, e := range parseNotifierCatalog(t) {
		known[e.key] = true
	}
	if len(known) < 40 {
		t.Fatalf("parsed only %d catalog entries; the guard cannot judge retired cases", len(known))
	}

	for _, c := range formatEventTypeCases(t) {
		if !known[c] {
			t.Errorf("formatEventType still labels %q, which no longer exists in Notifier::CATALOG", c)
		}
	}
}

func TestFormatEventTypeEchoesUnknownEvents(t *testing.T) {
	const unknown = "definitely_not_a_catalog_event"
	if got := stripANSI(formatEventType(unknown)); got != unknown {
		t.Fatalf("unknown event rendered as %q, want the raw key echoed back", got)
	}
}
