package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIsZipExtensionRecognisesTheDestinationsUsersType(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"lowercase", "backup.zip", true},
		{"uppercase", "BACKUP.ZIP", true},
		{"absolute path", "/home/u/out.zip", true},
		{"windows path", `C:\Users\u\out.zip`, true},
		{"dot only", ".", false},
		{"bare directory", "out", false},
		{"trailing separator", "out" + string(filepath.Separator), false},
		{"different archive format", "backup.tar.gz", false},
		{"zip in the middle", "backup.zip.bak", false},
		{"name is just zip", "zip", false},
		{"empty", "", false},
		{"trailing dot", "backup.", false},
		{"mixed case is not recognised", "backup.Zip", false},
		{"mixed case, other shape", "backup.zIP", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isZipExtension(tc.in); got != tc.want {
				t.Errorf("isZipExtension(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsZipExtensionReadsTheFinalSuffixOnly(t *testing.T) {
	for _, in := range []string{
		filepath.Join("archives.zip", "out"),
		filepath.Join("a.zip", "b.zip", "plain"),
	} {
		if isZipExtension(in) {
			t.Errorf("isZipExtension(%q) = true; only the last path segment's suffix counts", in)
		}
	}
	nested := filepath.Join("archives.zip", "out.zip")
	if !isZipExtension(nested) {
		t.Errorf("isZipExtension(%q) = false; the final segment is a zip", nested)
	}
}

func TestIsZipExtensionDependsOnlyOnTheSuffix(t *testing.T) {
	suffixes := []string{".zip", ".ZIP", ".Zip", ".txt", "", ".", ".tar.gz"}
	prefixes := []string{"", "a", "deep/dir/", "/abs/", "with space/"}
	for range 200 {
		suffix := suffixes[randInt(t, len(suffixes))]
		base := "name" + suffix
		want := isZipExtension(base)
		for _, p := range prefixes {
			in := p + base
			if got := isZipExtension(in); got != want {
				t.Fatalf("isZipExtension(%q) = %v but isZipExtension(%q) = %v; the prefix changed the answer",
					in, got, base, want)
			}
		}
		if got := isZipExtension(base); got != want {
			t.Fatalf("isZipExtension(%q) is not deterministic", base)
		}
		if strings.EqualFold(suffix, ".zip") && suffix != ".Zip" && !want {
			t.Fatalf("isZipExtension(%q) = false; the exactly-cased spellings must be recognised", base)
		}
	}
}
