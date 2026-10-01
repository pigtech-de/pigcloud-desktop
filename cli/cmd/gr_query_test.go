package cmd

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"
	"unicode/utf8"

	"pigcloud/internal/cmdutil"
	"pigcloud/internal/filetypes"

	"github.com/fatih/color"
)

func randInt(t *testing.T, n int) int {
	t.Helper()
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		t.Fatalf("rand: %v", err)
	}
	return int(v.Int64())
}

func TestTokenizeGrQueryNormalisesToTheIndexedShape(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"lowercases", "AuthService", []string{"authservice"}},
		{"splits on punctuation", "auth.service-token", []string{"auth", "service", "token"}},
		{"drops single chars", "a bc d ef", []string{"bc", "ef"}},
		{"deduplicates case variants", "Auth AUTH auth", []string{"auth"}},
		{"keeps first-appearance order", "zebra apple zebra mango", []string{"zebra", "apple", "mango"}},
		{"underscores and digits are word chars", "user_id42", []string{"user_id42"}},
		{"empty query", "", []string{}},
		{"punctuation only", "...---...", []string{}},
		{"non-ascii stays one token", "straße", []string{"straße"}},
		{"cjk is word content", "設定ファイル", []string{"設定ファイル"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tokenizeGrQuery(tc.raw)
			if len(got) != len(tc.want) {
				t.Fatalf("tokenizeGrQuery(%q) = %v, want %v", tc.raw, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("token %d = %q, want %q (full: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestTokenizeGrQueryPropertiesHoldOverRandomInput(t *testing.T) {
	alphabet := []rune("abcXYZ_019 .-/\t\nüß設")
	for range 200 {
		var sb strings.Builder
		for i := 0; i < randInt(t, 40); i++ {
			sb.WriteRune(alphabet[randInt(t, len(alphabet))])
		}
		raw := sb.String()
		got := tokenizeGrQuery(raw)

		seen := map[string]bool{}
		for _, tok := range got {
			if tok != strings.ToLower(tok) {
				t.Fatalf("query %q produced non-lowercase token %q; the index only holds lowercase", raw, tok)
			}
			if utf8.RuneCountInString(tok) < grMinTokenRunes {
				t.Fatalf("query %q produced token %q under the %d-character floor", raw, tok, grMinTokenRunes)
			}
			for _, r := range tok {
				if !isGrWordChar(r) {
					t.Fatalf("query %q produced token %q carrying separator %q", raw, tok, string(r))
				}
			}
			if seen[tok] {
				t.Fatalf("query %q emitted %q twice; duplicates re-scan the same token set", raw, tok)
			}
			seen[tok] = true
		}
	}
}

func TestTokenizeGrQueryFloorCountsCharactersNotBytes(t *testing.T) {
	tooShort := []string{"a", "Z", "9", "_", "ß", "設", "é", "Ω", "😀"}
	for _, in := range tooShort {
		if got := tokenizeGrQuery(in); len(got) != 0 {
			t.Errorf("tokenizeGrQuery(%q) = %v; one character is under the %d-char floor whatever it encodes to (%d bytes)",
				in, got, grMinTokenRunes, len(in))
		}
	}

	twoChars := map[string]string{
		"ab": "ab",
		"ßß": "ßß",
		"設定": "設定",
		"a1": "a1",
		"設a": "設a",
	}
	for in, want := range twoChars {
		got := tokenizeGrQuery(in)
		if len(got) != 1 || got[0] != want {
			t.Errorf("tokenizeGrQuery(%q) = %v, want [%q]; two characters clear the floor", in, got, want)
		}
	}
}

func TestGrMinTokenFloorMatchesTheIndexer(t *testing.T) {
	if grMinTokenRunes != 2 {
		t.Fatalf("grMinTokenRunes = %d; content-indexer.js emits [\\p{L}\\p{N}_]{2,}, so a different floor desyncs query from index",
			grMinTokenRunes)
	}
	boundary := strings.Repeat("設", grMinTokenRunes)
	if got := tokenizeGrQuery(boundary); len(got) != 1 {
		t.Errorf("a token of exactly %d characters must pass, got %v", grMinTokenRunes, got)
	}
	below := strings.Repeat("設", grMinTokenRunes-1)
	if got := tokenizeGrQuery(below); len(got) != 0 {
		t.Errorf("a token of %d characters must be dropped, got %v", grMinTokenRunes-1, got)
	}
}

func TestIsGrWordCharSplitsOnEverythingTheIndexerWould(t *testing.T) {
	for _, r := range "abzABZ019_" {
		if !isGrWordChar(r) {
			t.Errorf("%q must be word content", string(r))
		}
	}
	for _, r := range " \t\n.-/:,;()[]{}\"'" {
		if isGrWordChar(r) {
			t.Errorf("%q must split tokens", string(r))
		}
	}
	for _, r := range "üßé設定Ω" {
		if !isGrWordChar(r) {
			t.Errorf("non-ASCII rune %q must count as word content", string(r))
		}
	}
}

func TestMatchGrPayloadRequiresEveryQueryToken(t *testing.T) {
	payload := &grIndexContent{
		Tokens:   []string{"authentication", "token", "refresh"},
		Snippets: map[string]string{"authentication": "auth line", "token": "token line"},
	}

	if _, ok := matchGrPayload(payload, []string{"token", "refresh"}); !ok {
		t.Error("all-present query must match")
	}
	if _, ok := matchGrPayload(payload, []string{"token", "absent"}); ok {
		t.Error("a query token with no indexed counterpart must reject the whole file (AND, not OR)")
	}
	if _, ok := matchGrPayload(nil, []string{"token"}); ok {
		t.Error("nil payload must never match")
	}
	if _, ok := matchGrPayload(payload, nil); !ok {
		t.Error("an empty token list vacuously matches; the caller decides whether to ask")
	}
}

func TestMatchGrPayloadSubstringFallbackAndSnippets(t *testing.T) {
	payload := &grIndexContent{
		Tokens:   []string{"authentication", "token"},
		Snippets: map[string]string{"authentication": "auth snippet", "token": "token snippet"},
	}

	snips, ok := matchGrPayload(payload, []string{"auth"})
	if !ok {
		t.Fatal("prefix of an indexed token must match through the substring fallback")
	}
	if len(snips) != 1 || snips[0] != "auth snippet" {
		t.Errorf("fallback must carry the matched token's snippet, got %v", snips)
	}

	snips, ok = matchGrPayload(payload, []string{"token", "authentication"})
	if !ok {
		t.Fatal("exact tokens must match")
	}
	if len(snips) != 2 || snips[0] != "token snippet" || snips[1] != "auth snippet" {
		t.Errorf("snippets must follow query order, got %v", snips)
	}

	bare := &grIndexContent{Tokens: []string{"orphan"}, Snippets: map[string]string{}}
	snips, ok = matchGrPayload(bare, []string{"orphan"})
	if !ok {
		t.Error("a snippetless token must still count as a hit")
	}
	if len(snips) != 0 {
		t.Errorf("no snippet stored means no snippet emitted, got %v", snips)
	}
}

func TestIsGrepTargetTracksTheRegistry(t *testing.T) {
	exts := filetypes.Extensions()
	if len(exts) < 50 {
		t.Fatalf("registry returned only %d extensions; the accessor stopped enumerating", len(exts))
	}
	text := 0
	for _, ext := range exts {
		want := filetypes.IsText(ext)
		if want {
			text++
		}
		if got := isGrepTarget("file." + ext); got != want {
			t.Errorf("isGrepTarget(file.%s) = %v, registry says text=%v", ext, got, want)
		}
	}
	if text < 10 {
		t.Fatalf("only %d text extensions in the registry; the check is near-vacuous", text)
	}
}

func TestIsGrepTargetHandlesInputsTheRegistryNeverHolds(t *testing.T) {
	var textExt, binExt string
	for _, ext := range filetypes.Extensions() {
		if strings.ToUpper(ext) == ext {
			continue
		}
		if textExt == "" && filetypes.IsText(ext) {
			textExt = ext
		}
		if binExt == "" && !filetypes.IsText(ext) {
			binExt = ext
		}
	}
	if textExt == "" || binExt == "" {
		t.Fatal("registry lacks a lowercase text and non-text extension to build case variants from")
	}

	upper := strings.ToUpper(textExt)
	mixed := strings.ToUpper(textExt[:1]) + textExt[1:]
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"uppercase extension", "NOTES." + upper, true},
		{"mixed-case extension", "Notes." + mixed, true},
		{"uppercase non-text", "BLOB." + strings.ToUpper(binExt), false},
		{"path, not bare name", "/deep/dir/notes." + textExt, true},
		{"windows path", `C:\Users\x\notes.` + textExt, true},
		{"no extension at all", "Makefile", false},
		{"trailing dot", "notes.", false},
		{"empty name", "", false},
		{"bare extension used as the whole name", textExt, false},
		{"compound suffix reads the last segment", "archive.tar." + textExt, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isGrepTarget(tc.in); got != tc.want {
				t.Errorf("isGrepTarget(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestGrepBytesNumbersLinesFromOne(t *testing.T) {
	m, err := cmdutil.CompileMatcher("needle", cmdutil.MatchFixed, false)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	got := grepBytes([]byte("alpha\nneedle here\nbeta\nsecond needle"), m)
	if len(got) != 2 {
		t.Fatalf("want 2 matches, got %d: %v", len(got), got)
	}
	if got[0].lineNum != 2 {
		t.Errorf("first match on line %d, want 2 (grep line numbers are 1-based)", got[0].lineNum)
	}
	if got[0].line != "needle here" {
		t.Errorf("first match line = %q", got[0].line)
	}
	if got[1].lineNum != 4 || got[1].line != "second needle" {
		t.Errorf("unterminated final line lost: %+v", got[1])
	}
	if len(grepBytes(nil, m)) != 0 {
		t.Error("empty input must produce no matches")
	}
}

func TestGrepBytesCaseFoldingComesFromTheMatcher(t *testing.T) {
	sensitive, _ := cmdutil.CompileMatcher("NEEDLE", cmdutil.MatchFixed, false)
	insensitive, _ := cmdutil.CompileMatcher("NEEDLE", cmdutil.MatchFixed, true)
	data := []byte("a needle b")

	if n := len(grepBytes(data, sensitive)); n != 0 {
		t.Errorf("case-sensitive matcher found %d matches, want 0", n)
	}
	if n := len(grepBytes(data, insensitive)); n != 1 {
		t.Errorf("-i matcher found %d matches, want 1", n)
	}
}

func TestHighlightMatchWrapsOnlyTheMatchedSpan(t *testing.T) {
	saved := color.NoColor
	color.NoColor = false
	t.Cleanup(func() { color.NoColor = saved })

	fixed, _ := cmdutil.CompileMatcher("dle", cmdutil.MatchFixed, false)
	out := highlightMatch("a needle b", fixed)
	if out == "a needle b" {
		t.Fatal("fixed-mode match was not highlighted")
	}
	if !strings.Contains(out, "a nee") || !strings.Contains(out, " b") {
		t.Errorf("unmatched text was altered: %q", out)
	}

	glob, err := cmdutil.CompileMatcher("*.txt", cmdutil.MatchGlob, false)
	if err != nil {
		t.Fatalf("compile glob: %v", err)
	}
	if got := highlightMatch("a needle b", glob); got != "a needle b" {
		t.Errorf("glob mode must pass the line through verbatim, got %q", got)
	}
}

func TestHighlightMatchLeavesNonMatchingLinesAlone(t *testing.T) {
	m, _ := cmdutil.CompileMatcher("zzz", cmdutil.MatchFixed, false)
	const line = "nothing to see"
	if got := highlightMatch(line, m); got != line {
		t.Errorf("non-matching line changed: %q", got)
	}
}
