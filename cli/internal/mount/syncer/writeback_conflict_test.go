package syncer

import (
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func conflictFixture(t *testing.T) (*WritebackProcessor, *cache.DB, int64) {
	t.Helper()
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	id, err := db.UpsertInode(&cache.Inode{
		RemotePath:  "docs/notes.txt",
		DisplayName: "notes.txt",
		Size:        10,
		Mtime:       time.Now().Unix(),
		Dirty:       true,
		SyncStatus:  cache.StatusConflict,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(id, "upload", "docs/notes.txt", ""); err != nil {
		t.Fatal(err)
	}
	return NewWritebackProcessor(nil, nil, db, nil, ""), db, id
}

func TestHeldByConflict(t *testing.T) {
	w, db, id := conflictFixture(t)

	entries, err := db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
	}
	if !w.heldByConflict(entries[0]) {
		t.Fatal("conflicted upload not held")
	}

	db.SetSyncStatus(id, cache.StatusPending, "")
	if w.heldByConflict(entries[0]) {
		t.Fatal("resolved upload still held")
	}
}

func TestFlushAllTerminatesOnHeldEntries(t *testing.T) {
	w, db, id := conflictFixture(t)

	done := make(chan struct{})
	var res FlushResult
	var err error
	go func() {
		res, err = w.FlushAll(5 * time.Second)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("FlushAll live-locked on a held conflict entry")
	}
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if res.Flushed != 0 {
		t.Fatalf("flushed = %d, want 0 (upload held)", res.Flushed)
	}

	entries, _ := db.DequeueWriteback(10, 0)
	if len(entries) != 1 || entries[0].InodeID != id {
		t.Fatalf("held entry lost from the queue (got %d entries)", len(entries))
	}
}
