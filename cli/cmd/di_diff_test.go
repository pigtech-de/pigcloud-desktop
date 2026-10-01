package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/api"
)

func opsOf(lines []diffLine) string {
	var sb strings.Builder
	for _, l := range lines {
		switch l.op {
		case diffEqual:
			sb.WriteByte(' ')
		case diffAdd:
			sb.WriteByte('+')
		case diffRemove:
			sb.WriteByte('-')
		}
	}
	return sb.String()
}

func linesOnly(lines []diffLine, op int) []string {
	var out []string
	for _, l := range lines {
		if l.op == op {
			out = append(out, l.line)
		}
	}
	return out
}

func TestSimpleDiffOnIdenticalInputIsEmpty(t *testing.T) {
	body := []string{"alpha", "beta", "gamma"}
	if got := simpleDiff(body, body); len(got) != 0 {
		t.Errorf("identical files must produce no diff output, got %v", opsOf(got))
	}
	if got := simpleDiff(nil, nil); len(got) != 0 {
		t.Errorf("two empty files must produce no diff, got %v", opsOf(got))
	}
}

func TestSimpleDiffOnEmptySides(t *testing.T) {
	body := []string{"a", "b"}
	added := simpleDiff(nil, body)
	if opsOf(added) != "++" {
		t.Errorf("empty to content = %q, want ++", opsOf(added))
	}
	removed := simpleDiff(body, nil)
	if opsOf(removed) != "--" {
		t.Errorf("content to empty = %q, want --", opsOf(removed))
	}
}

func TestSimpleDiffTrimsUnchangedLinesToThreeOfContext(t *testing.T) {
	var a []string
	for i := range 40 {
		a = append(a, "line"+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	b := append([]string(nil), a...)
	b[20] = "CHANGED"

	got := simpleDiff(a, b)
	if len(got) >= len(a) {
		t.Fatalf("diff kept %d of %d lines; the context filter did nothing", len(got), len(a))
	}
	if adds := linesOnly(got, diffAdd); len(adds) != 1 || adds[0] != "CHANGED" {
		t.Errorf("adds = %v, want exactly [CHANGED]", adds)
	}
	if rems := linesOnly(got, diffRemove); len(rems) != 1 || rems[0] != a[20] {
		t.Errorf("removes = %v, want exactly [%s]", rems, a[20])
	}
	ctx := len(linesOnly(got, diffEqual))
	if ctx > 8 {
		t.Errorf("%d context lines kept around one change; the 3-line window is not bounding it", ctx)
	}
	if ctx == 0 {
		t.Error("no context kept; the change has nothing to orient against")
	}
}

func TestSimpleDiffKeepsContextAtTheFileEdges(t *testing.T) {
	a := []string{"one", "two", "three", "four", "five"}
	b := []string{"CHANGED", "two", "three", "four", "five"}
	got := simpleDiff(a, b)

	if len(got) == 0 {
		t.Fatal("a change on the first line produced no output")
	}
	if adds := linesOnly(got, diffAdd); len(adds) != 1 || adds[0] != "CHANGED" {
		t.Errorf("adds = %v", adds)
	}
	ctxLines := linesOnly(got, diffEqual)
	if len(ctxLines) != 3 || ctxLines[0] != "two" {
		t.Errorf("context = %v, want the 3 lines after the change", ctxLines)
	}
}

func TestSimpleDiffSidesReconstructTheirInputs(t *testing.T) {
	words := []string{"alpha", "beta", "gamma", "delta", "epsilon"}
	for range 200 {
		mk := func() []string {
			out := make([]string, 0, 8)
			for i := 0; i < randInt(t, 9); i++ {
				out = append(out, words[randInt(t, len(words))])
			}
			return out
		}
		a, b := mk(), mk()
		got := simpleDiff(a, b)

		var fromA, fromB []string
		for _, l := range got {
			if l.op != diffAdd {
				fromA = append(fromA, l.line)
			}
			if l.op != diffRemove {
				fromB = append(fromB, l.line)
			}
		}
		if !isSubsequence(fromA, a) {
			t.Fatalf("the removed+context side is not a subsequence of A\nA=%v B=%v\nside=%v", a, b, fromA)
		}
		if !isSubsequence(fromB, b) {
			t.Fatalf("the added+context side is not a subsequence of B\nA=%v B=%v\nside=%v", a, b, fromB)
		}
		if equalStrings(a, b) && len(got) != 0 {
			t.Fatalf("identical inputs %v produced a diff %v", a, opsOf(got))
		}
		if !equalStrings(a, b) && len(got) == 0 {
			t.Fatalf("different inputs produced no diff\nA=%v\nB=%v", a, b)
		}
	}
}

func isSubsequence(sub, full []string) bool {
	i := 0
	for _, s := range full {
		if i < len(sub) && sub[i] == s {
			i++
		}
	}
	return i == len(sub)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestResolveVersionArgMapsDisplayNumbersToRowIDs(t *testing.T) {
	versions := []api.VersionEntry{
		{ID: 907, VersionNumber: 1},
		{ID: 412, VersionNumber: 2},
		{ID: 3, VersionNumber: 3},
	}
	cases := map[string]string{
		"1":  "907",
		"2":  "412",
		"v2": "412",
		"V2": "412",
		"3":  "3",
	}
	for arg, want := range cases {
		if got := resolveVersionArg(versions, arg, "/f.txt"); got != want {
			t.Errorf("resolveVersionArg(%q) = %q, want %q", arg, got, want)
		}
	}
	if got := resolveVersionArg(versions, "", "/f.txt"); got != "" {
		t.Errorf("an empty arg must stay empty (the server picks the default), got %q", got)
	}
}

func TestResolveVersionArgFallsBackToRawRowIDs(t *testing.T) {
	versions := []api.VersionEntry{
		{ID: 907, VersionNumber: 1},
		{ID: 412, VersionNumber: 2},
	}
	if got := resolveVersionArg(versions, "412", "/f.txt"); got != "412" {
		t.Errorf("raw row id = %q, want 412", got)
	}

	ambiguous := []api.VersionEntry{
		{ID: 2, VersionNumber: 1},
		{ID: 55, VersionNumber: 2},
	}
	if got := resolveVersionArg(ambiguous, "2", "/f.txt"); got != "55" {
		t.Errorf("resolveVersionArg(2) = %q; the displayed version number must beat a colliding row id (want 55)", got)
	}
}

func TestResolveVersionArgRefusesUnknownAndMalformedInput(t *testing.T) {
	versions := []api.VersionEntry{{ID: 907, VersionNumber: 1}}

	if exited := expectExit(t, func() { resolveVersionArg(versions, "nope", "/f.txt") }); !exited {
		t.Error("a non-numeric version must refuse, not be silently coerced")
	}
	if exited := expectExit(t, func() { resolveVersionArg(versions, "99", "/f.txt") }); !exited {
		t.Error("a version that does not exist must refuse")
	}
	if exited := expectExit(t, func() { resolveVersionArg(nil, "1", "/f.txt") }); !exited {
		t.Error("an empty version list must refuse rather than return an empty id")
	}
}

func TestReadLinesSplitsOnNewlinesAndKeepsBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := os.WriteFile(path, []byte("one\n\nthree\r\nfour"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readLines(path)
	if err != nil {
		t.Fatalf("readLines: %v", err)
	}
	want := []string{"one", "", "three", "four"}
	if len(got) != len(want) {
		t.Fatalf("readLines = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadLinesOnAnEmptyFileAndAMissingFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := readLines(empty)
	if err != nil {
		t.Fatalf("readLines(empty): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("empty file = %#v, want no lines", got)
	}

	if _, err := readLines(filepath.Join(dir, "absent.txt")); err == nil {
		t.Error("a missing file must report an error, not an empty diff side")
	}
}

func TestReadLinesHandlesLinesPastTheScannerDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "long.txt")
	long := strings.Repeat("x", 300*1024)
	if err := os.WriteFile(path, []byte("head\n"+long+"\ntail"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := readLines(path)
	if err != nil {
		t.Fatalf("readLines: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d lines, want 3", len(got))
	}
	if len(got[1]) != len(long) {
		t.Errorf("long line truncated to %d bytes, want %d", len(got[1]), len(long))
	}
}
