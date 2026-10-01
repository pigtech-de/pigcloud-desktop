package cmdutil

import (
	"testing"

	"pigcloud/internal/api"
)

func walkFixture() []api.TreeEntry {
	return []api.TreeEntry{
		{Name: "notes.txt", Type: "file"},
		{Name: "docs", Type: "directory", Children: []api.TreeEntry{
			{Name: "readme.md", Type: "file"},
			{Name: "img", Type: "directory", Children: []api.TreeEntry{
				{Name: "logo.png", Type: "file"},
			}},
		}},
		{Name: "empty", Type: "directory"},
	}
}

func collectWalk(entries []api.TreeEntry, root string) ([]string, []string) {
	var remote, rel []string
	WalkTreeFiles(entries, root, func(_ api.TreeEntry, remotePath, relPath string) {
		remote = append(remote, remotePath)
		rel = append(rel, relPath)
	})
	return remote, rel
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

func TestWalkTreeFilesAtRoot(t *testing.T) {
	remote, rel := collectWalk(walkFixture(), "/")

	wantRemote := []string{"/notes.txt", "/docs/readme.md", "/docs/img/logo.png"}
	wantRel := []string{"notes.txt", "docs/readme.md", "docs/img/logo.png"}
	if !equalStrings(remote, wantRemote) {
		t.Errorf("remote paths at root = %q, want %q", remote, wantRemote)
	}
	if !equalStrings(rel, wantRel) {
		t.Errorf("relative paths at root = %q, want %q", rel, wantRel)
	}
}

func TestWalkTreeFilesNested(t *testing.T) {
	remote, rel := collectWalk(walkFixture(), "/Documents/Archive")

	wantRemote := []string{
		"/Documents/Archive/notes.txt",
		"/Documents/Archive/docs/readme.md",
		"/Documents/Archive/docs/img/logo.png",
	}
	wantRel := []string{"notes.txt", "docs/readme.md", "docs/img/logo.png"}
	if !equalStrings(remote, wantRemote) {
		t.Errorf("remote paths = %q, want %q", remote, wantRemote)
	}
	if !equalStrings(rel, wantRel) {
		t.Errorf("relative paths = %q, want %q", rel, wantRel)
	}
}

func TestWalkTreeFilesSkipsEmptyTree(t *testing.T) {
	calls := 0
	WalkTreeFiles(nil, "/", func(api.TreeEntry, string, string) { calls++ })
	if calls != 0 {
		t.Errorf("callback ran %d times for an empty tree", calls)
	}
}

func TestJoinRemotePath(t *testing.T) {
	cases := []struct{ root, rel, want string }{
		{"/", "a.txt", "/a.txt"},
		{"", "a.txt", "/a.txt"},
		{"/Docs", "a.txt", "/Docs/a.txt"},
		{"/Docs/", "a.txt", "/Docs/a.txt"},
		{"/Docs", "sub/a.txt", "/Docs/sub/a.txt"},
		{"/Docs", "", "/Docs"},
	}
	for _, c := range cases {
		if got := JoinRemotePath(c.root, c.rel); got != c.want {
			t.Errorf("JoinRemotePath(%q, %q) = %q, want %q", c.root, c.rel, got, c.want)
		}
	}
}
