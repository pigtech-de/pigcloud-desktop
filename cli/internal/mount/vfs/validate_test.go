package vfs

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"pigcloud/internal/filetypes"
)

func TestNameRuleMatchesSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../../tests/vectors/name_rule_v1.json")
	if err != nil {
		t.Fatalf("read shared name vectors: %v", err)
	}
	type nameSet struct {
		Accept []string `json:"accept"`
		Reject []string `json:"reject"`
	}
	var vectors struct {
		Folder nameSet `json:"folder"`
		File   nameSet `json:"file"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse shared name vectors: %v", err)
	}
	for kind, re := range map[string]*regexp.Regexp{"folder": validFolderRegex, "file": validNameRegex} {
		set := vectors.Folder
		if kind == "file" {
			set = vectors.File
		}
		if len(set.Accept) == 0 || len(set.Reject) == 0 {
			t.Fatalf("%s vectors are empty; this guard would be vacuous", kind)
		}
		for _, name := range set.Accept {
			if !re.MatchString(name) {
				t.Errorf("%s rule rejects %q, which PHP and JS accept", kind, name)
			}
		}
		for _, name := range set.Reject {
			if re.MatchString(name) {
				t.Errorf("%s rule accepts %q, which PHP and JS reject", kind, name)
			}
		}
	}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func TestValidateFile_ExtensionsTrackRegistry(t *testing.T) {
	exts := filetypes.Extensions()
	if len(exts) == 0 {
		t.Fatal("registry exposed no extensions; this guard would be vacuous")
	}
	sort.Strings(exts)

	for _, ext := range exts {
		name := "test." + ext
		if !validNameRegex.MatchString(name) {
			continue
		}
		ok, reason := ValidateFile(name, 1024)
		if !ok {
			t.Errorf("ValidateFile(%q) = false (%q) but %q is a registry extension of type %q",
				name, reason, ext, filetypes.TypeOf(ext))
		}
	}

	for _, ext := range []string{"fakeext123", "qqqqqqq", "definitely-not-a-real-ext"} {
		if filetypes.TypeOf(ext) != "other" {
			t.Fatalf("%q is now a registry extension; pick another unknown for this guard", ext)
		}
		name := "test." + ext
		if ok, _ := ValidateFile(name, 1024); ok {
			t.Errorf("ValidateFile(%q) = true for an extension absent from the registry", name)
		}
	}
}

func TestValidateFile_ExtensionCaseDoesNotChangeTheVerdict(t *testing.T) {
	exts := filetypes.Extensions()
	if len(exts) == 0 {
		t.Fatal("registry exposed no extensions; this guard would be vacuous")
	}
	sort.Strings(exts)

	checked := 0
	for _, ext := range exts {
		upper := strings.ToUpper(ext)
		if upper == ext {
			continue
		}
		if ok, _ := ValidateFile("test."+ext, 1024); !ok {
			continue
		}
		checked++
		for _, variant := range []string{upper, capitalize(ext)} {
			name := "test." + variant
			if ok, reason := ValidateFile(name, 1024); !ok {
				t.Errorf("ValidateFile(%q) = false (%q) but the lowercase %q is accepted", name, reason, "test."+ext)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no registry extension had a distinct uppercase form; this guard would be vacuous")
	}
}

func TestValidateFile_UppercaseRegressionCases(t *testing.T) {
	for _, name := range []string{"IMG_1234.JPG", "CLIP.MP4", "Scan.PDF", "Notes.TXT"} {
		t.Run(name, func(t *testing.T) {
			if ok, reason := ValidateFile(name, 1024); !ok {
				t.Errorf("ValidateFile(%q) = false (%q); camera and Windows files must sync", name, reason)
			}
		})
	}
}

func TestValidateFile_UnknownExtensionRejectedInAnyCase(t *testing.T) {
	for _, name := range []string{"x.qqqqqqq", "x.QQQQQQQ", "x.QqQqQqQ"} {
		t.Run(name, func(t *testing.T) {
			if ok, _ := ValidateFile(name, 1024); ok {
				t.Errorf("ValidateFile(%q) = true for an extension absent from the registry", name)
			}
		})
	}
}

func TestValidateFile_SizeLimit(t *testing.T) {
	if ok, _ := ValidateFile("big.pdf", MaxUploadSize+1); ok {
		t.Errorf("file above MaxUploadSize must be rejected")
	}
	if ok, _ := ValidateFile("zero.png", 0); !ok {
		t.Errorf("zero-byte file must be accepted")
	}
}

func TestValidateFile_NameCharacters(t *testing.T) {
	if ok, _ := ValidateFile("bad name?.txt", 1024); ok {
		t.Errorf("name with ?-character must be rejected (matches REGEX_FILE_NAME)")
	}
	if ok, reason := ValidateFile("Geschäftsbericht.pdf", 1024); !ok {
		t.Errorf("umlaut name must be accepted: %s", reason)
	}
}

func TestValidateFile_ExtensionlessAllowed(t *testing.T) {
	for _, name := range []string{"no-ext-file", "Makefile", "LICENSE", "README"} {
		t.Run(name, func(t *testing.T) {
			if ok, _ := ValidateFile(name, 1024); !ok {
				t.Errorf("extensionless file %q must be accepted", name)
			}
		})
	}
}

func TestValidateDirName(t *testing.T) {
	tests := []struct {
		name   string
		wantOK bool
	}{
		{"Documents", true},
		{"My Photos", true},
		{"test-dir", true},
		{"test_dir", true},
		{"Geschäftsberichte", true},
		{"bad/name", false},
		{"bad.name", false},
		{"bad@name", false},
	}
	for _, tc := range tests {
		ok, _ := ValidateDirName(tc.name)
		if ok != tc.wantOK {
			t.Errorf("ValidateDirName(%q) = %v, want %v", tc.name, ok, tc.wantOK)
		}
	}
}

func TestIsExcludedDir(t *testing.T) {
	if !IsExcludedDir(".Trash") {
		t.Error(".Trash should be excluded")
	}
	if !IsExcludedDir(".Favorites") {
		t.Error(".Favorites should be excluded")
	}
	if !IsExcludedDir(".Recents") {
		t.Error(".Recents should be excluded")
	}
	if IsExcludedDir("Documents") {
		t.Error("Documents should not be excluded")
	}
}
