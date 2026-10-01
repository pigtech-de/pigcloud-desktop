package vfs

import (
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func TestNodeConstructors(t *testing.T) {
	root := NewRootNode("Photos")
	if !root.IsDir || root.Name != "/" || root.RemotePath != "Photos" || root.Children == nil {
		t.Errorf("root: %+v", root)
	}
	if root.SyncStatus != cache.StatusSynced {
		t.Errorf("root status = %v", root.SyncStatus)
	}

	dir := NewDirNode("Sub", "Photos/Sub", root)
	if !dir.IsDir || dir.Parent != root || dir.Mode != 0755 || dir.Children == nil {
		t.Errorf("dir: %+v", dir)
	}

	mtime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	file := NewFileNode("a.txt", "Photos/a.txt", 42, mtime, dir)
	if file.IsDir || file.Size != 42 || !file.Mtime.Equal(mtime) || file.Mode != 0644 || file.Parent != dir {
		t.Errorf("file: %+v", file)
	}
}

func TestNodeChildOps(t *testing.T) {
	root := NewRootNode("")
	parent := NewFileNode("p", "p", 0, time.Now(), nil)
	parent.IsDir = true
	child := NewFileNode("c.txt", "p/c.txt", 1, time.Now(), nil)
	parent.AddChild(child)
	if got := parent.GetChild("c.txt"); got != child {
		t.Fatal("child not retrievable after AddChild on nil map")
	}
	if child.Parent != parent {
		t.Error("AddChild did not reparent")
	}

	a := NewFileNode("a", "a", 0, time.Now(), root)
	b := NewDirNode("b", "b", root)
	root.AddChild(a)
	root.AddChild(b)
	if root.ChildCount() != 2 {
		t.Errorf("count = %d", root.ChildCount())
	}
	names := map[string]bool{}
	for _, n := range root.ListChildren() {
		names[n.Name] = true
	}
	if !names["a"] || !names["b"] {
		t.Errorf("ListChildren = %v", names)
	}
	root.RemoveChild("a")
	if root.GetChild("a") != nil || root.ChildCount() != 1 {
		t.Error("RemoveChild did not remove")
	}
	if root.GetChild("missing") != nil {
		t.Error("missing child not nil")
	}
}

func TestNodeFullPath(t *testing.T) {
	cases := []struct {
		remote string
		want   string
	}{
		{"", "/"},
		{"/", "/"},
		{"Docs", "/Docs"},
		{"Docs/report.pdf", "/Docs/report.pdf"},
	}
	for _, c := range cases {
		n := &Node{RemotePath: c.remote}
		if got := n.FullPath(); got != c.want {
			t.Errorf("FullPath(%q) = %q, want %q", c.remote, got, c.want)
		}
	}
}

func TestJoinPath(t *testing.T) {
	if got := joinPath("", "a.txt"); got != "a.txt" {
		t.Errorf("root join: %q", got)
	}
	if got := joinPath("Docs", "a.txt"); got != "Docs/a.txt" {
		t.Errorf("nested join: %q", got)
	}
	if got := joinPath("Docs/Sub", "x"); got != "Docs/Sub/x" {
		t.Errorf("deep join: %q", got)
	}
}
