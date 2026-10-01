package cmd

import (
	"fmt"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/tree"
)

func trNode(id int, name, parent string, isDir bool) *tree.Node {
	return &tree.Node{ID: fmt.Sprintf("%032x", id), Name: name, ParentID: parent, IsDir: isDir}
}

func flattenNames(entries []api.TreeEntry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Name)
		out = append(out, flattenNames(e.Children)...)
	}
	return out
}

func TestLocalTreeEntriesMatchTheServerWalkShape(t *testing.T) {
	docs := fmt.Sprintf("%032x", 1)
	reports := fmt.Sprintf("%032x", 2)
	hidden := trNode(4, "Secrets", docs, true)
	hidden.Hidden = true
	trashed := trNode(6, "gone.txt", docs, false)
	trashed.Trashed = true
	built := tree.New([]*tree.Node{
		trNode(1, "Docs", "", true),
		trNode(2, "Reports", docs, true),
		trNode(3, "note.txt", docs, false),
		hidden,
		trNode(5, "inside-secrets.txt", hidden.ID, false),
		trashed,
		trNode(7, "q1.pdf", reports, false),
	})

	entries := localTreeEntries(built, docs, 3, false, false)
	got := flattenNames(entries)
	want := []string{"Reports", "q1.pdf", "note.txt"}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entries = %v, want %v", got, want)
		}
	}
	if entries[0].Type != "directory" || entries[1].Type != "file" {
		t.Fatalf("types = %s/%s, want directory/file", entries[0].Type, entries[1].Type)
	}

	all := flattenNames(localTreeEntries(built, docs, 3, false, true))
	if len(all) != 5 {
		t.Fatalf("showAll entries = %v, want hidden subtree included, trashed still out", all)
	}

	dirsOnly := flattenNames(localTreeEntries(built, docs, 3, true, false))
	if len(dirsOnly) != 1 || dirsOnly[0] != "Reports" {
		t.Fatalf("dirsOnly entries = %v, want [Reports]", dirsOnly)
	}

	if depthCapped := localTreeEntries(built, docs, 1, false, false); len(depthCapped) != 2 || depthCapped[0].Children != nil {
		t.Fatalf("depth 1 must list children without recursing, got %+v", depthCapped)
	}
	if zero := localTreeEntries(built, docs, 0, false, false); zero != nil {
		t.Fatalf("depth 0 must be empty, got %+v", zero)
	}
}
