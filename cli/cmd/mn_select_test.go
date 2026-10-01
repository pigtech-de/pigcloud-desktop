package cmd

import (
	"strings"
	"testing"

	"pigcloud/internal/mount"
)

func withShellMode(t *testing.T) {
	t.Helper()
	saved := shellMode
	SetShellMode(true)
	t.Cleanup(func() { SetShellMode(saved) })
}

func expectExit(t *testing.T, fn func()) (exited bool) {
	t.Helper()
	withShellMode(t)
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		if r != "command_error" {
			panic(r)
		}
		exited = true
	}()
	fn()
	return false
}

func mounts(remotes ...string) []*mount.MountInfo {
	out := make([]*mount.MountInfo, 0, len(remotes))
	for _, r := range remotes {
		out = append(out, &mount.MountInfo{RemotePath: r, MountPoint: "/mnt" + r, Mode: mount.ModeSync})
	}
	return out
}

func TestSelectMountInPicksTheLongestMatchingPrefix(t *testing.T) {
	withShellMode(t)
	set := mounts("/Photos", "/Photos/2026", "/Docs")

	cases := []struct {
		name string
		hint string
		want string
	}{
		{"exact match", "/Photos", "/Photos"},
		{"exact match on the deeper mount", "/Photos/2026", "/Photos/2026"},
		{"file inside the shallow mount", "/Photos/old/a.jpg", "/Photos"},
		{"file inside the deep mount wins over its parent", "/Photos/2026/may/a.jpg", "/Photos/2026"},
		{"unnormalised hint", "Docs/notes.txt", "/Docs"},
		{"trailing-slash-free sibling is not a prefix", "/Docs", "/Docs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selectMountIn(set, tc.hint)
			if got == nil {
				t.Fatalf("selectMountIn(%q) = nil, want %s", tc.hint, tc.want)
			}
			if !sameRemote(got.RemotePath, tc.want) {
				t.Errorf("selectMountIn(%q) = %s, want %s", tc.hint, got.RemotePath, tc.want)
			}
		})
	}
}

func TestSelectMountInRequiresASegmentBoundary(t *testing.T) {
	set := mounts("/Photos")
	if exited := expectExit(t, func() { selectMountIn(set, "/PhotosOld/a.jpg") }); !exited {
		t.Error("a name-prefix sibling must not match; the command should refuse")
	}
}

func TestSelectMountInRootMountSwallowsEveryPath(t *testing.T) {
	set := mounts("/")
	for _, hint := range []string{"/anything/deep.txt", "anything", "/"} {
		got := selectMountIn(set, hint)
		if got == nil {
			t.Fatalf("root mount did not answer for %q", hint)
		}
	}

	both := mounts("/", "/Photos")
	got := selectMountIn(both, "/Photos/a.jpg")
	if got == nil || !sameRemote(got.RemotePath, "/Photos") {
		t.Fatalf("deep mount must beat the root mount inside its subtree, got %v", got)
	}
	got = selectMountIn(both, "/Docs/a.txt")
	if got == nil || !sameRemote(got.RemotePath, "/") {
		t.Fatalf("root mount must catch paths outside every deeper mount, got %v", got)
	}
}

func TestSelectMountInEmptyHintNeedsExactlyOneCandidate(t *testing.T) {
	if got := selectMountIn(nil, ""); got != nil {
		t.Errorf("no mounts must yield nil, not a refusal: %v", got)
	}
	if got := selectMountIn(nil, "/Photos"); got != nil {
		t.Errorf("no mounts must yield nil even with a hint: %v", got)
	}

	single := mounts("/Photos")
	if got := selectMountIn(single, ""); got == nil || !sameRemote(got.RemotePath, "/Photos") {
		t.Errorf("a lone mount must be picked without a hint, got %v", got)
	}

	if exited := expectExit(t, func() { selectMountIn(mounts("/Photos", "/Docs"), "") }); !exited {
		t.Error("an ambiguous empty hint must refuse rather than guess a mount")
	}
}

func TestSelectMountInUnmatchedHintRefuses(t *testing.T) {
	if exited := expectExit(t, func() { selectMountIn(mounts("/Photos", "/Docs"), "/Music") }); !exited {
		t.Error("a hint matching no mount must refuse")
	}
}

func TestDisplayRemoteAlwaysRendersAnAbsolutePath(t *testing.T) {
	cases := map[string]string{
		"":              "/",
		"/":             "/",
		"Photos":        "/Photos",
		"/Photos":       "/Photos",
		"/Photos/2026":  "/Photos/2026",
		"Photos/2026":   "/Photos/2026",
		"/a/b/c/d.txt":  "/a/b/c/d.txt",
		"with space/x":  "/with space/x",
		"ümlaut/dätei":  "/ümlaut/dätei",
		"trailing/dir/": "/trailing/dir/",
	}
	for in, want := range cases {
		if got := displayRemote(in); got != want {
			t.Errorf("displayRemote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRemoteNormalisationPropertiesHoldOverRandomPaths(t *testing.T) {
	segments := []string{"a", "Photos", "2026", "with space", "ü", "x.txt"}
	for range 200 {
		parts := make([]string, 0, 4)
		for i := 0; i < 1+randInt(t, 4); i++ {
			parts = append(parts, segments[randInt(t, len(segments))])
		}
		bare := strings.Join(parts, "/")
		slashed := "/" + bare

		if !sameRemote(bare, slashed) {
			t.Fatalf("sameRemote(%q, %q) = false; the leading slash must not fork the key", bare, slashed)
		}
		if got := displayRemote(displayRemote(bare)); got != displayRemote(bare) {
			t.Fatalf("displayRemote is not idempotent for %q: %q then %q", bare, displayRemote(bare), got)
		}
		if d := displayRemote(bare); !strings.HasPrefix(d, "/") {
			t.Fatalf("displayRemote(%q) = %q, must be absolute", bare, d)
		}
		if !sameRemote(bare, bare) {
			t.Fatalf("sameRemote is not reflexive for %q", bare)
		}
	}
}

func TestSameRemoteSeparatesDistinctPaths(t *testing.T) {
	if sameRemote("/Photos", "/Photos/2026") {
		t.Error("a parent and its child are different mounts")
	}
	if sameRemote("/Photos", "/photos") {
		t.Error("remote paths are case-sensitive; folding them would collide two mounts")
	}
	if !sameRemote("/", "") {
		t.Error("root spells as both / and empty")
	}
	if sameRemote("//Photos", "/Photos") {
		t.Error("a doubled leading slash no longer forks the mount key; update the registry key docs")
	}
}

func TestParentOfStripsTheLastSegment(t *testing.T) {
	cases := map[string]string{
		"Screenshots/img.png":   "Screenshots",
		"a/b/c.txt":             "a/b",
		"test.txt":              "",
		"":                      "",
		"/leading.txt":          "",
		"/a/b.txt":              "/a",
		"trailing/":             "trailing",
		"dir/sub/deep/file.bin": "dir/sub/deep",
	}
	for in, want := range cases {
		if got := parentOf(in); got != want {
			t.Errorf("parentOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParentOfTerminatesForAnyPath(t *testing.T) {
	segments := []string{"a", "bb", "c c", "ü", ""}
	for range 200 {
		parts := make([]string, 0, 6)
		for i := 0; i < 1+randInt(t, 6); i++ {
			parts = append(parts, segments[randInt(t, len(segments))])
		}
		p := strings.Join(parts, "/")
		steps := 0
		for p != "" {
			next := parentOf(p)
			if len(next) >= len(p) {
				t.Fatalf("parentOf(%q) = %q did not shorten the path", p, next)
			}
			p = next
			steps++
			if steps > 64 {
				t.Fatalf("parentOf did not terminate from the original path")
			}
		}
	}
}
