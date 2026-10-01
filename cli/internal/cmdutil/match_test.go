package cmdutil

import "testing"

func mustCompile(t *testing.T, pattern string, mode MatchMode, ignoreCase bool) *Matcher {
	t.Helper()
	m, err := CompileMatcher(pattern, mode, ignoreCase)
	if err != nil {
		t.Fatalf("CompileMatcher(%q, %v, %v): %v", pattern, mode, ignoreCase, err)
	}
	if m == nil {
		t.Fatalf("CompileMatcher(%q) returned no matcher and no error", pattern)
	}
	return m
}

func TestGlobMatchesWholeNameNotSubstring(t *testing.T) {
	cases := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*.txt", "report.txt", true},
		{"*.txt", "report.txt.bak", false},
		{"*.txt", "report.txtx", false},
		{"draft*", "draft1", true},
		{"draft*", "final draft1", false},
		{"draft*", "Draft1", false},
		{"?.txt", "a.txt", true},
		{"?.txt", "ab.txt", false},
		{"?.txt", ".txt", false},
		{"report.*", "report.txt", true},
		{"report.*", "myreport.txt", false},
		{"*", "anything", true},
		{"*", "", true},
	}
	for _, tc := range cases {
		m := mustCompile(t, tc.pattern, MatchGlob, false)
		if got := m.MatchString(tc.name); got != tc.want {
			t.Errorf("glob %q vs %q = %v, want %v", tc.pattern, tc.name, got, tc.want)
		}
	}
}

func TestGlobIgnoreCaseFoldsBothSides(t *testing.T) {
	sensitive := mustCompile(t, "*.TXT", MatchGlob, false)
	if sensitive.MatchString("report.txt") {
		t.Error("case-sensitive glob matched a differently-cased name")
	}

	folded := mustCompile(t, "*.TXT", MatchGlob, true)
	if !folded.MatchString("report.txt") {
		t.Error("ignore-case glob did not fold the target")
	}
	lowerPattern := mustCompile(t, "*.txt", MatchGlob, true)
	if !lowerPattern.MatchString("REPORT.TXT") {
		t.Error("ignore-case glob did not fold the pattern")
	}
}

func TestFixedModeIsLiteralSubstring(t *testing.T) {
	m := mustCompile(t, "a*b", MatchFixed, false)
	if !m.MatchString("xxa*byy") {
		t.Error("fixed mode did not find its literal as a substring")
	}
	if m.MatchString("aXb") {
		t.Error("fixed mode expanded * as a wildcard")
	}
	if m.MatchString("ab") {
		t.Error("fixed mode matched with the literal * absent")
	}

	dotted := mustCompile(t, "a.b", MatchFixed, false)
	if dotted.MatchString("aXb") {
		t.Error("fixed mode treated . as a regex metacharacter")
	}
	if !dotted.MatchString("a.b") {
		t.Error("fixed mode did not match its own literal")
	}

	folded := mustCompile(t, "A.B", MatchFixed, true)
	if !folded.MatchString("xxa.byy") {
		t.Error("ignore-case fixed mode did not fold")
	}
}

func TestGlobModeDoesNotInterpretRegexSyntax(t *testing.T) {
	m := mustCompile(t, "a.b", MatchGlob, false)
	if m.MatchString("aXb") {
		t.Error("glob mode treated . as a regex metacharacter")
	}
	if !m.MatchString("a.b") {
		t.Error("glob mode did not match its own literal name")
	}
}

func TestRegexModeCompilesAndRejects(t *testing.T) {
	if _, err := CompileMatcher("([unclosed", MatchRegex, false); err == nil {
		t.Fatal("an invalid regex compiled without error")
	}

	m := mustCompile(t, `^report-\d+\.txt$`, MatchRegex, false)
	if !m.MatchString("report-42.txt") {
		t.Error("regex did not match a name it describes")
	}
	if m.MatchString("report-x.txt") {
		t.Error("regex matched a name it does not describe")
	}

	sensitive := mustCompile(t, "^REPORT$", MatchRegex, false)
	if sensitive.MatchString("report") {
		t.Error("case-sensitive regex matched a differently-cased name")
	}
	folded := mustCompile(t, "^REPORT$", MatchRegex, true)
	if !folded.MatchString("report") {
		t.Error("ignore-case regex did not fold")
	}
}

func TestModesDisagreeOnAnchoringAsDocumented(t *testing.T) {
	word := "draft"
	glob := mustCompile(t, word, MatchGlob, false)
	if glob.MatchString("draft final") {
		t.Error("glob matched a name longer than the pattern")
	}
	if !glob.MatchString("draft") {
		t.Error("glob did not match the exact name")
	}

	re := mustCompile(t, word, MatchRegex, false)
	if !re.MatchString("draft final") {
		t.Error("regex mode stopped behaving as an unanchored search")
	}
}

func TestInvalidGlobIsRejectedAtCompileTime(t *testing.T) {
	malformed := []string{"a[b", "[", "[a", "[]", "*[", "[^", "[!", "x[y-", "?[", `a\`}
	for _, pattern := range malformed {
		m, err := CompileMatcher(pattern, MatchGlob, false)
		if err == nil {
			t.Errorf("CompileMatcher(%q, MatchGlob) accepted a malformed pattern", pattern)
		}
		if m != nil {
			t.Errorf("CompileMatcher(%q, MatchGlob) returned a matcher alongside its verdict", pattern)
		}
	}

	for _, pattern := range []string{"*.txt", "draft*", "?.txt", "[a-z]*", "report.*", "*", "plain"} {
		if _, err := CompileMatcher(pattern, MatchGlob, false); err != nil {
			t.Errorf("CompileMatcher(%q, MatchGlob) rejected a valid pattern: %v", pattern, err)
		}
	}
}

func TestGlobThatFailsOnlyAtMatchTimeMatchesNothing(t *testing.T) {
	const pattern = "[a]*["
	m, err := CompileMatcher(pattern, MatchGlob, false)
	if err != nil {
		t.Skipf("%q now fails at compile time, so the runtime arm is unreachable", pattern)
	}

	for _, name := range []string{"a[a]*[", "a[a]*[b", "ab[a]*["} {
		if m.MatchString(name) {
			t.Errorf("malformed glob %q matched %q; the matcher fell back to a rule the pattern never expressed", pattern, name)
		}
	}
}

func TestHighlightRegexPerMode(t *testing.T) {
	if got := mustCompile(t, "*.txt", MatchGlob, false).HighlightRegex(); got != nil {
		t.Errorf("glob mode produced a highlight regex %v, want nil", got)
	}

	fixed := mustCompile(t, "a.b", MatchFixed, false).HighlightRegex()
	if fixed == nil {
		t.Fatal("fixed mode produced no highlight regex")
	}
	if fixed.MatchString("aXb") {
		t.Error("fixed-mode highlight regex left . unescaped")
	}
	if !fixed.MatchString("a.b") {
		t.Error("fixed-mode highlight regex does not match its own literal")
	}

	re := mustCompile(t, `^report-\d+$`, MatchRegex, false).HighlightRegex()
	if re == nil {
		t.Fatal("regex mode produced no highlight regex")
	}
	if !re.MatchString("report-7") {
		t.Error("regex-mode highlight regex is not the compiled pattern")
	}
}

func TestHighlightRegexAgreesWithMatchStringOnFixedIgnoreCase(t *testing.T) {
	m := mustCompile(t, "Report", MatchFixed, true)
	const name = "QUARTERLY REPORT"
	if !m.MatchString(name) {
		t.Fatal("ignore-case fixed matcher missed its target")
	}
	hl := m.HighlightRegex()
	if hl == nil {
		t.Fatal("no highlight regex for ignore-case fixed mode")
	}
	if !hl.MatchString(name) {
		t.Error("highlight regex misses a name MatchString accepted")
	}
}
