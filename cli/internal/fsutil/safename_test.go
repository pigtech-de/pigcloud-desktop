package fsutil

import "testing"

func TestIsSafeName_Escapes(t *testing.T) {
	for _, bad := range []string{
		"", ".", "..", "../etc", "a/b", "a\\b", "x\x00y",
		"a\tb", "\x1b]52;c;aGk=\x07a.pdf", "a\x7fb", "a\u0085b", "a\u009bb", "a\x9bb",
	} {
		if IsSafeName(bad) || IsDisplaySafeName(bad) {
			t.Errorf("%q passed the name guard, want refused on every platform", bad)
		}
	}
	for _, good := range []string{"report.txt", "Fotos", "my_file-1.pdf", "Größe ä.txt"} {
		if !IsSafeName(good) {
			t.Errorf("IsSafeName(%q) = false, want true", good)
		}
	}
}

func TestIsDisplaySafeName_IgnoresPlatformRules(t *testing.T) {
	for _, name := range []string{"CON.txt", "NUL.log", "notes.", "a ", "a:b"} {
		if !IsDisplaySafeName(name) {
			t.Errorf("IsDisplaySafeName(%q) = false, want true", name)
		}
	}
}

func TestStripControl(t *testing.T) {
	if got := StripControl("\x1b]52;c;aGk=\x07a.pdf\u009b"); got != "]52;c;aGk=a.pdf" {
		t.Fatalf("StripControl = %q", got)
	}
	if got := StripControl("a\x9bb"); got != "a�b" {
		t.Fatalf("StripControl kept a stray 0x9b byte: %q", got)
	}
	if got := StripControl("plain ä"); got != "plain ä" {
		t.Fatalf("StripControl changed clean text: %q", got)
	}
}
