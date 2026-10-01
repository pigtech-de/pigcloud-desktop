package crypto

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestPathTokenPathsDepths(t *testing.T) {
	cases := []struct {
		name  string
		path  string
		depth PathTokenDepth
		want  []string
	}{
		{"self only", "a/b/c.txt", PathTokenSelfOnly, []string{"a/b/c.txt"}},
		{"self and parent", "a/b/c.txt", PathTokenSelfAndParent, []string{"a/b/c.txt", "a/b"}},
		{"self and ancestors", "a/b/c.txt", PathTokenSelfAndAncestors, []string{"a/b/c.txt", "a/b", "a"}},
		{"top level parent stops at root", "a.txt", PathTokenSelfAndParent, []string{"a.txt"}},
		{"top level ancestors stop at root", "a.txt", PathTokenSelfAndAncestors, []string{"a.txt"}},
		{"leading slash trimmed", "/a/b", PathTokenSelfAndParent, []string{"a/b", "a"}},
		{"backslashes folded", `a\b\c`, PathTokenSelfAndAncestors, []string{"a/b/c", "a/b", "a"}},
		{"root", "/", PathTokenSelfAndAncestors, nil},
		{"empty", "", PathTokenSelfAndParent, nil},
		{"double leading slash", "//a/b", PathTokenSelfAndParent, []string{"a/b", "a"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := PathTokenPaths(tc.path, tc.depth)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("PathTokenPaths(%q, %v) = %v, want %v", tc.path, tc.depth, got, tc.want)
			}
		})
	}
}

func TestPathTokenPathsSelfOnlyNeverWalksUp(t *testing.T) {
	got := PathTokenPaths("photos/2026/trip/img.jpg", PathTokenSelfOnly)
	if len(got) != 1 || got[0] != "photos/2026/trip/img.jpg" {
		t.Fatalf("self-only returned %v", got)
	}
}

func TestAddPathTokenOptions(t *testing.T) {
	nameKey := make([]byte, NameKeySize)
	for i := range nameKey {
		nameKey[i] = byte(i)
	}

	options := map[string]string{}
	AddPathTokenOptions(options, nameKey, PathTokenPaths("a/b", PathTokenSelfAndParent))

	var tokens map[string]string
	if err := json.Unmarshal([]byte(options["path_tokens"]), &tokens); err != nil {
		t.Fatalf("path_tokens is not JSON: %v", err)
	}
	if len(tokens) != 2 {
		t.Fatalf("want tokens for a/b and a, got %v", tokens)
	}
	for _, p := range []string{"a/b", "a"} {
		want, err := ComputePathToken(nameKey, p)
		if err != nil {
			t.Fatal(err)
		}
		if tokens[p] != hexOf(want) {
			t.Fatalf("token for %q = %q, want %q", p, tokens[p], hexOf(want))
		}
	}
	if _, ok := options["path_tokens_legacy"]; ok {
		t.Fatal("plain ASCII paths must not carry a legacy map")
	}
}

func TestAddPathTokenOptionsLegacyForAffectedPath(t *testing.T) {
	nameKey := make([]byte, NameKeySize)
	options := map[string]string{}
	AddPathTokenOptions(options, nameKey, PathTokenPaths("İstanbul/x", PathTokenSelfAndParent))
	if options["path_tokens_legacy"] == "" {
		t.Fatal("U+0130 path must offer the legacy token map")
	}
}

func TestAddPathTokenOptionsNoKeyNoOptions(t *testing.T) {
	options := map[string]string{}
	AddPathTokenOptions(options, nil, []string{"a/b"})
	if len(options) != 0 {
		t.Fatalf("no name key must add nothing, got %v", options)
	}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}
