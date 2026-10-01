package syncer

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"pigcloud/internal/mount/cache"
)

func TestShouldIgnore(t *testing.T) {
	cases := []struct {
		name   string
		ignore bool
	}{
		{".DS_Store", true},
		{"Thumbs.db", true},
		{"desktop.ini", true},
		{"~$report.docx", true},
		{".pig-abc.tmp", true},
		{"draft.swp", true},
		{"file.tmp", true},
		{"movie.crdownload", true},
		{"archive.part", true},
		{".hidden", true},
		{".git", true},
		{"report.txt", false},
		{"photo.jpg", false},
		{"Makefile", false},
	}
	for _, c := range cases {
		if got := shouldIgnore(c.name); got != c.ignore {
			t.Errorf("shouldIgnore(%q) = %v, want %v", c.name, got, c.ignore)
		}
	}
}

func TestWatcherToRemotePath(t *testing.T) {
	syncDir := t.TempDir()

	nested := &Watcher{syncDir: syncDir, remotePath: "Docs"}
	if got := nested.toRemotePath(filepath.Join(syncDir, "a", "b.txt")); got != "Docs/a/b.txt" {
		t.Errorf("nested toRemotePath = %q, want Docs/a/b.txt", got)
	}

	root := &Watcher{syncDir: syncDir, remotePath: ""}
	if got := root.toRemotePath(filepath.Join(syncDir, "top.txt")); got != "top.txt" {
		t.Errorf("root toRemotePath = %q, want top.txt", got)
	}
}

func TestHandleRemoveDecision(t *testing.T) {
	cases := []struct {
		status      cache.SyncStatus
		wantDelete  bool
		wantTracked bool
	}{
		{cache.StatusSynced, true, true},
		{cache.StatusConflict, true, true},
		{cache.StatusPending, false, false},
		{cache.StatusRejected, false, false},
		{cache.StatusFailed, false, false},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			syncDir := t.TempDir()
			db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db}

			db.UpsertInode(&cache.Inode{RemotePath: "x.txt", DisplayName: "x.txt", Size: 3, SyncStatus: c.status})
			w.handleRemove(context.Background(), filepath.Join(syncDir, "x.txt"))

			pending, _ := db.PendingWritebackCount()
			gotDelete := false
			ents, _ := db.DequeueWriteback(10, 0)
			for _, e := range ents {
				if e.Action == "delete" {
					gotDelete = true
				}
			}
			if gotDelete != c.wantDelete {
				t.Errorf("delete queued = %v, want %v (pending=%d)", gotDelete, c.wantDelete, pending)
			}
			in, _ := db.GetInodeByPath("x.txt")
			if (in != nil) != c.wantTracked {
				t.Errorf("tracked = %v, want %v", in != nil, c.wantTracked)
			}
		})
	}

	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db}
	w.handleRemove(context.Background(), filepath.Join(syncDir, "ghost.txt"))
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("untracked remove queued %d writebacks", n)
	}
}

func TestSyncFileCoalescing(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}

	path := filepath.Join(syncDir, "note.txt")
	writeFile(t, path, "hello world")
	w.syncFile(path)
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Fatalf("valid change queued %d, want 1", n)
	}
	in, _ := db.GetInodeByPath("note.txt")
	if in == nil || !in.Dirty || in.SyncStatus != cache.StatusPending {
		t.Fatalf("valid change not tracked dirty+pending: %+v", in)
	}

	db.DequeueWriteback(10, 0)
	db.SetSyncStatus(in.ID, cache.StatusSynced, "")
	db.MarkCached(in.ID, in.ContentHash)
	w.syncFile(path)
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("identical re-save of a synced file queued %d, want 0", n)
	}

	badPath := filepath.Join(syncDir, "bad@name.txt")
	writeFile(t, badPath, "nope")
	w.syncFile(badPath)
	if bin, _ := db.GetInodeByPath("bad@name.txt"); bin == nil || bin.SyncStatus != cache.StatusRejected {
		t.Errorf("unsupported name not tracked rejected: %+v", bin)
	}
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("rejected file queued a writeback: %d", n)
	}
}

func TestSyncFileReleasesSupersededBlob(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}

	path := filepath.Join(syncDir, "doc.txt")
	writeFile(t, path, "version one")
	w.syncFile(path)
	in, _ := db.GetInodeByPath("doc.txt")
	if in == nil || in.ContentHash == "" {
		t.Fatalf("first save not stored: %+v", in)
	}
	first := in.ContentHash
	db.MarkSynced(in.ID, "")
	db.MarkCached(in.ID, first)

	writeFile(t, path, "version two, which is longer")
	w.syncFile(path)
	after, _ := db.GetInodeByPath("doc.txt")
	if after == nil || after.ContentHash == first {
		t.Fatalf("edit did not supersede the blob: %+v", after)
	}
	if store.Has(first) {
		t.Errorf("superseded blob %s still on disk after the edit", first)
	}
	if !store.Has(after.ContentHash) {
		t.Error("current blob was released instead of the superseded one")
	}
}

func TestSyncFileKeepsBlobSharedWithAnotherInode(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}

	a := filepath.Join(syncDir, "a.txt")
	b := filepath.Join(syncDir, "b.txt")
	writeFile(t, a, "same bytes")
	writeFile(t, b, "same bytes")
	w.syncFile(a)
	w.syncFile(b)

	ia, _ := db.GetInodeByPath("a.txt")
	ib, _ := db.GetInodeByPath("b.txt")
	if ia == nil || ib == nil || ia.ContentHash != ib.ContentHash {
		t.Fatalf("identical files did not share a blob: %+v / %+v", ia, ib)
	}
	shared := ia.ContentHash
	db.MarkCached(ia.ID, shared)
	db.MarkCached(ib.ID, shared)

	writeFile(t, a, "a diverges now")
	w.syncFile(a)
	if !store.Has(shared) {
		t.Errorf("blob %s still referenced by b.txt was released", shared)
	}
}

func TestSyncFileStreamsMultiChunkFile(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}

	data := make([]byte, 3*1024*1024+321)
	for i := range data {
		data[i] = byte(i*29 + 11)
	}
	path := filepath.Join(syncDir, "big.bin")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	w.syncFile(path)

	in, _ := db.GetInodeByPath("big.bin")
	if in == nil || in.ContentHash == "" {
		t.Fatalf("multi-chunk file not stored: %+v", in)
	}
	got, err := store.Get(in.ContentHash)
	if err != nil {
		t.Fatalf("Get stored blob: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("stored blob does not round-trip the original bytes")
	}
}
