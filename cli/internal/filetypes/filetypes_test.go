package filetypes

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func registryFromEmbedded(t *testing.T) map[string]string {
	t.Helper()
	var reg struct {
		Extensions map[string]struct {
			Type string `json:"type"`
		} `json:"extensions"`
	}
	if err := json.Unmarshal(rawJSON, &reg); err != nil {
		t.Fatalf("parse embedded file-types.json: %v", err)
	}
	if len(reg.Extensions) == 0 {
		t.Fatal("embedded registry has no extensions; every guard below would be vacuous")
	}
	out := make(map[string]string, len(reg.Extensions))
	for ext, entry := range reg.Extensions {
		out[ext] = entry.Type
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestTypeOfMatchesTheRegistryForEveryExtension(t *testing.T) {
	reg := registryFromEmbedded(t)
	for _, ext := range sortedKeys(reg) {
		want := reg[ext]
		if want == "" {
			t.Errorf("registry entry %q has no type", ext)
			continue
		}
		if want == "other" {
			t.Errorf("registry entry %q uses the sentinel type \"other\"; known and unknown extensions become indistinguishable", ext)
		}
		if got := TypeOf(ext); got != want {
			t.Errorf("TypeOf(%q) = %q, registry says %q", ext, got, want)
		}
	}
}

func TestIsTextTracksTheRegistry(t *testing.T) {
	reg := registryFromEmbedded(t)
	text, nonText := 0, 0
	for _, ext := range sortedKeys(reg) {
		want := reg[ext] == "text"
		if want {
			text++
		} else {
			nonText++
		}
		if got := IsText(ext); got != want {
			t.Errorf("IsText(%q) = %v, registry type is %q", ext, got, reg[ext])
		}
	}
	if text == 0 || nonText == 0 {
		t.Fatalf("registry covered only one side (text=%d, non-text=%d)", text, nonText)
	}
}

func TestEmbeddedRegistryMatchesTheRepositorySourceOfTruth(t *testing.T) {
	src := filepath.Join("..", "..", "..", "private", "file-types.json")
	want, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("repository registry not reachable from this tree: %v", err)
	}
	if !bytes.Equal(want, rawJSON) {
		t.Errorf("the embedded copy of file-types.json differs from %s, so the CLI would classify files differently than the server; re-run the Makefile copy step", src)
	}
}

func TestTypeOfOnlyAnswersForExactRegistryKeys(t *testing.T) {
	reg := registryFromEmbedded(t)

	sample := ""
	for _, ext := range sortedKeys(reg) {
		if strings.ToUpper(ext) != ext {
			sample = ext
			break
		}
	}
	if sample == "" {
		t.Fatal("registry has no extension with a lowercase letter; the case guard below would be vacuous")
	}

	cases := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"unknown extension", "definitely-not-a-real-extension"},
		{"leading dot", "." + sample},
		{"uppercased", strings.ToUpper(sample)},
		{"trailing space", sample + " "},
		{"leading space", " " + sample},
		{"whole filename", "photo." + sample},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, isKey := reg[tc.in]; isKey {
				t.Skipf("%q is itself a registry key", tc.in)
			}
			if got := TypeOf(tc.in); got != "other" {
				t.Errorf("TypeOf(%q) = %q, want \"other\"", tc.in, got)
			}
			if IsText(tc.in) {
				t.Errorf("IsText(%q) = true for a non-registry key", tc.in)
			}
		})
	}

	if _, isKey := reg["tar.gz"]; !isKey {
		if got := TypeOf("tar.gz"); got != "other" {
			t.Errorf("TypeOf(%q) = %q; TypeOf takes one extension segment, not a compound suffix", "tar.gz", got)
		}
	}
}
