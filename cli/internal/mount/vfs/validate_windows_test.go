//go:build windows

package vfs

import "testing"

func TestIsSafeNameWindows(t *testing.T) {
	bad := []string{
		"CON", "con", "nul.txt", "PRN", "AUX", "COM1", "LPT9.log",
		`a:b.txt`, "a*b", "a?b", `a"b`, "a<b", "a>b", "a|b",
		"trailingdot.", "trailingspace ", "ctrl\x01x",
	}
	for _, n := range bad {
		if IsSafeName(n) {
			t.Errorf("IsSafeName(%q) = true on Windows, want false", n)
		}
	}

	good := []string{"report.txt", "CONsole.txt", "com0.txt", "my-file_1.pdf", "Geschäft.pdf"}
	for _, n := range good {
		if !IsSafeName(n) {
			t.Errorf("IsSafeName(%q) = false on Windows, want true", n)
		}
	}
}
