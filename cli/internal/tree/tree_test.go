package tree

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
)

func node(id, name, parent string, isDir bool) *Node {
	return &Node{ID: id, Name: name, ParentID: parent, IsDir: isDir}
}

func hexID(n int) string { return fmt.Sprintf("%032x", n) }

func TestChildrenAreFoldersFirstThenCaseInsensitiveName(t *testing.T) {
	tr := New([]*Node{
		node(hexID(1), "zebra.txt", "", false),
		node(hexID(2), "Apple", "", true),
		node(hexID(3), "beta.txt", "", false),
		node(hexID(4), "zeta", "", true),
	})
	var got []string
	for _, n := range tr.Children("") {
		got = append(got, n.Name)
	}
	want := []string{"Apple", "zeta", "beta.txt", "zebra.txt"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("child order = %v, want %v", got, want)
		}
	}
}

func TestResolveWalksPathCaseInsensitively(t *testing.T) {
	tr := New([]*Node{
		node(hexID(1), "Docs", "", true),
		node(hexID(2), "Reports", hexID(1), true),
		node(hexID(3), "q1.pdf", hexID(2), false),
	})
	got, err := tr.Resolve("docs/REPORTS/Q1.pdf")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ID != hexID(3) {
		t.Fatalf("resolved %s, want %s", got.ID, hexID(3))
	}
	if path := tr.PathOf(got.ID); path != "Docs/Reports/q1.pdf" {
		t.Fatalf("PathOf = %q", path)
	}
	if _, err := tr.Resolve("docs/nope"); err != ErrNotFound {
		t.Fatalf("missing path error = %v, want ErrNotFound", err)
	}
}

func TestResolveSkipsTrashedNodes(t *testing.T) {
	trashed := node(hexID(1), "Docs", "", true)
	trashed.Trashed = true
	tr := New([]*Node{trashed})
	if _, err := tr.Resolve("Docs"); err != ErrNotFound {
		t.Fatalf("a trashed node must not resolve by path, got %v", err)
	}
}

func TestDescendantsCoverTheWholeSubtreeAndExcludeTheRoot(t *testing.T) {
	tr := New([]*Node{
		node(hexID(1), "Docs", "", true),
		node(hexID(2), "a", hexID(1), true),
		node(hexID(3), "b.txt", hexID(2), false),
		node(hexID(4), "c.txt", hexID(1), false),
		node(hexID(5), "elsewhere.txt", "", false),
	})
	got := map[string]bool{}
	for _, id := range tr.Descendants(hexID(1)) {
		got[id] = true
	}
	for _, want := range []string{hexID(2), hexID(3), hexID(4)} {
		if !got[want] {
			t.Errorf("descendant %s missing", want)
		}
	}
	if got[hexID(1)] {
		t.Error("the root must not be in its own descendant list")
	}
	if got[hexID(5)] {
		t.Error("an unrelated node leaked into the cascade list")
	}
}

func TestSubtreeIsDepthFirstInDisplayOrder(t *testing.T) {
	tr := New([]*Node{
		node(hexID(1), "Docs", "", true),
		node(hexID(2), "zeta", hexID(1), true),
		node(hexID(3), "Apple", hexID(1), true),
		node(hexID(4), "a.txt", hexID(1), false),
		node(hexID(5), "deep.txt", hexID(3), false),
		node(hexID(6), "elsewhere.txt", "", false),
	})
	got := tr.Subtree(hexID(1), true)
	want := []string{hexID(3), hexID(5), hexID(2), hexID(4)}
	if len(got) != len(want) {
		t.Fatalf("Subtree = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Subtree = %v, want %v", got, want)
		}
	}
}

func TestSubtreePrunesHiddenSubtreesAndSkipsTrashed(t *testing.T) {
	hiddenDir := node(hexID(2), "Hidden", hexID(1), true)
	hiddenDir.Hidden = true
	trashed := node(hexID(4), "gone.txt", hexID(1), false)
	trashed.Trashed = true
	tr := New([]*Node{
		node(hexID(1), "Docs", "", true),
		hiddenDir,
		node(hexID(3), "inside-hidden.txt", hexID(2), false),
		trashed,
		node(hexID(5), "kept.txt", hexID(1), false),
	})

	got := tr.Subtree(hexID(1), false)
	if len(got) != 1 || got[0] != hexID(5) {
		t.Fatalf("pruned Subtree = %v, want only %s: a visible file under a hidden folder must prune with it", got, hexID(5))
	}

	all := tr.Subtree(hexID(1), true)
	want := map[string]bool{hexID(2): true, hexID(3): true, hexID(5): true}
	if len(all) != len(want) {
		t.Fatalf("includeHidden Subtree = %v, want %v (trashed always excluded)", all, want)
	}
	for _, id := range all {
		if !want[id] {
			t.Fatalf("includeHidden Subtree = %v carries unexpected %s", all, id)
		}
	}
}

func TestAMissingParentKeepsTheNodeAsAnOrphan(t *testing.T) {
	tr := New([]*Node{node(hexID(2), "stray.txt", hexID(99), false)})
	if _, ok := tr.Get(hexID(2)); !ok {
		t.Fatal("a node with an unknown parent must be kept, never dropped")
	}
	if len(tr.Orphans) != 1 || tr.Orphans[0] != hexID(2) {
		t.Fatalf("orphans = %v", tr.Orphans)
	}
	if len(tr.Children("")) != 1 {
		t.Fatal("an orphan must stay reachable from the root")
	}
}

func TestACycleTerminatesAndStaysReachable(t *testing.T) {
	tr := New([]*Node{
		node(hexID(1), "a", hexID(2), true),
		node(hexID(2), "b", hexID(1), true),
	})
	if tr.Len() != 2 {
		t.Fatalf("cycle members must be kept, got %d nodes", tr.Len())
	}
	done := make(chan struct{})
	go func() {
		tr.Descendants("")
		tr.PathOf(hexID(1))
		close(done)
	}()
	<-done
	if len(tr.Children("")) == 0 {
		t.Fatal("a cycle must be re-rooted so its members stay reachable")
	}
}

type fakeExec struct {
	pages []shellPage
	calls int
}

func (f *fakeExec) Execute(_ context.Context, command string, _ map[string]string) (*api.Response, error) {
	if command != "e2ee_list_shells" {
		return nil, fmt.Errorf("unexpected command %q", command)
	}
	page := f.pages[f.calls]
	f.calls++
	raw, _ := json.Marshal(page)
	return &api.Response{Success: true, Raw: raw}, nil
}

func TestFetchDecryptsSealedNamesAndParents(t *testing.T) {
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer priv.Zero()
	parentKey, err := crypto.DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}

	folderID, fileID := hexID(1), hexID(2)
	folderBytes, _ := IDBytes(folderID)
	fileBytes, _ := IDBytes(fileID)

	sealName := func(name string) string {
		sealed, err := crypto.SealDisplayName(name, pub)
		if err != nil {
			t.Fatalf("SealDisplayName: %v", err)
		}
		return base64.StdEncoding.EncodeToString(sealed)
	}
	sealParent := func(parent, self []byte) string {
		sealed, err := crypto.SealParentRef(parent, self, parentKey)
		if err != nil {
			t.Fatalf("SealParentRef: %v", err)
		}
		return base64.StdEncoding.EncodeToString(sealed)
	}

	client := &fakeExec{pages: []shellPage{{
		Shells: []Shell{
			{NodeID: folderID, ItemType: "directory", DisplayName: sealName("Docs"),
				SealedParent: sealParent(nil, folderBytes), PlaintextParent: hexID(77)},
			{NodeID: fileID, ItemType: "file", DisplayName: sealName("q1.pdf"),
				SealedParent: sealParent(folderBytes, fileBytes), PlaintextParent: hexID(77)},
		},
		Done: true,
	}}}

	tr, err := Fetch(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, err := tr.Resolve("Docs/q1.pdf")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.ID != fileID {
		t.Fatalf("resolved %s, want %s", got.ID, fileID)
	}
	if folder, _ := tr.Get(folderID); folder.ParentID != "" {
		t.Fatalf("sealed root ref lost to the plaintext column: parent=%q", folder.ParentID)
	}
}

func TestFetchKeepsANodeWhoseNameWillNotUnseal(t *testing.T) {
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer priv.Zero()
	parentKey, _ := crypto.DeriveParentKey(priv)

	other, otherPriv, _ := crypto.GenerateHybridKeyPair()
	defer otherPriv.Zero()
	foreignName, _ := crypto.SealDisplayName("secret.txt", other)
	_ = pub

	client := &fakeExec{pages: []shellPage{{
		Shells: []Shell{{
			NodeID: hexID(3), ItemType: "file",
			DisplayName: base64.StdEncoding.EncodeToString(foreignName),
		}},
		Done: true,
	}}}

	tr, err := Fetch(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, ok := tr.Get(hexID(3))
	if !ok {
		t.Fatal("an unsealable name must not drop the node")
	}
	if got.Name != "(encrypted)" {
		t.Fatalf("placeholder name = %q", got.Name)
	}
}

func TestFetchWalksEveryPage(t *testing.T) {
	_, priv, _ := crypto.GenerateHybridKeyPair()
	defer priv.Zero()
	parentKey, _ := crypto.DeriveParentKey(priv)
	cursor := hexID(1)
	client := &fakeExec{pages: []shellPage{
		{Shells: []Shell{{NodeID: hexID(1), ItemType: "file"}}, NextCursor: &cursor},
		{Shells: []Shell{{NodeID: hexID(2), ItemType: "file"}}, Done: true},
	}}
	tr, err := Fetch(context.Background(), client, Keys{Priv: priv, ParentKey: parentKey})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if tr.Len() != 2 {
		t.Fatalf("walked %d nodes, want 2 across both pages", tr.Len())
	}
	if client.calls != 2 {
		t.Fatalf("made %d calls, want 2", client.calls)
	}
}
