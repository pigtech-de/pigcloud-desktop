package syncer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestReconcilerHealsDrift(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	r := NewReconciler(syncDir, "", db, time.Minute)

	writeFile(t, filepath.Join(syncDir, "untracked.txt"), "hello")

	writeFile(t, filepath.Join(syncDir, "failed.txt"), "retry me")
	db.UpsertInode(&cache.Inode{RemotePath: "failed.txt", DisplayName: "failed.txt", Size: 8, SyncStatus: cache.StatusFailed})

	writeFile(t, filepath.Join(syncDir, "edited.txt"), "now longer than before")
	editID, _ := db.UpsertInode(&cache.Inode{RemotePath: "edited.txt", DisplayName: "edited.txt", Size: 3, Cached: true, ContentHash: "oldhash", SyncStatus: cache.StatusSynced, Etag: "v1"})
	db.SetLocalContent(editID, digestOf("old"), 0)

	writeFile(t, filepath.Join(syncDir, "clean.txt"), "stable")
	cleanID, _ := db.UpsertInode(&cache.Inode{RemotePath: "clean.txt", DisplayName: "clean.txt", Size: 6, Cached: true, ContentHash: "h", SyncStatus: cache.StatusSynced, Etag: "v1"})
	db.SetLocalContent(cleanID, digestOf("stable"), 0)

	healed := r.Reconcile(context.Background())
	if healed != 3 {
		t.Fatalf("healed=%d, want 3 (untracked, failed, edited)", healed)
	}

	entries, err := db.DequeueWriteback(100, 0)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	queued := map[string]bool{}
	for _, e := range entries {
		if e.Action == "upload" {
			queued[e.RemotePath] = true
		}
	}
	for _, p := range []string{"untracked.txt", "failed.txt", "edited.txt"} {
		if !queued[p] {
			t.Errorf("%s was not queued for upload", p)
		}
	}
	if queued["clean.txt"] {
		t.Error("clean.txt (size matches) must not be re-queued")
	}

	if in, _ := db.GetInodeByPath("failed.txt"); in == nil || in.SyncStatus != cache.StatusPending {
		t.Errorf("failed.txt not reset to pending")
	}
	if in, _ := db.GetInodeByPath("edited.txt"); in == nil || in.ContentHash != "" || in.Size != 22 {
		t.Errorf("edited.txt re-queue should clear hash and refresh size, got %+v", in)
	}
}

func TestReconcilerSkipsPermanentUploadFailure(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	r := NewReconciler(syncDir, "", db, time.Minute)

	writeFile(t, filepath.Join(syncDir, "perm.txt"), "over quota")
	pid, _ := db.UpsertInode(&cache.Inode{RemotePath: "perm.txt", DisplayName: "perm.txt", Size: 9, SyncStatus: cache.StatusFailed})
	db.EnqueueWriteback(pid, "upload", "perm.txt", "")
	permEntries, _ := db.DequeueWriteback(10, 0)
	db.UpdateWriteback(permEntries[0].ID, "failed", "over quota", maxRetries)
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: pid, Kind: cache.FailureUpload, Permanent: true, Attempts: maxRetries, LastError: "over quota"})

	writeFile(t, filepath.Join(syncDir, "trans.txt"), "retry me")
	tid, _ := db.UpsertInode(&cache.Inode{RemotePath: "trans.txt", DisplayName: "trans.txt", Size: 8, SyncStatus: cache.StatusFailed})
	db.EnqueueWriteback(tid, "upload", "trans.txt", "")
	db.EnqueueWriteback(tid, "delete", "trans-old.txt", "")
	transEntries, _ := db.DequeueWriteback(10, 0)
	var transKey string
	for _, e := range transEntries {
		if e.Action == "upload" {
			transKey = cache.UploadKeyFromExtra(e.ExtraJSON)
		}
		db.UpdateWriteback(e.ID, "failed", "502 bad gateway", maxRetries)
	}
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: tid, Kind: cache.FailureUpload, Permanent: false, Attempts: maxRetries, LastError: "502 bad gateway"})

	if healed := r.Reconcile(context.Background()); healed != 1 {
		t.Fatalf("healed=%d, want 1 (only the transient one)", healed)
	}

	if in, _ := db.GetInodeByPath("perm.txt"); in == nil || in.SyncStatus != cache.StatusFailed {
		t.Errorf("perm.txt should stay failed, got %+v", in)
	}
	pending, _ := db.PendingWritebackCount()
	if pending != 1 {
		t.Fatalf("want 1 pending (the transient retry), got %d", pending)
	}
	failed, _ := db.FailedWritebackCount()
	if failed != 2 {
		t.Fatalf("want 2 failed rows (perm upload + trans delete), got %d", failed)
	}

	retry, _ := db.DequeueWriteback(10, 0)
	if len(retry) != 1 || retry[0].Action != "upload" || retry[0].InodeID != tid {
		t.Fatalf("unexpected retry entries: %+v", retry)
	}
	if k := cache.UploadKeyFromExtra(retry[0].ExtraJSON); k == "" || k == transKey {
		t.Fatalf("requeue must mint a fresh idempotency key: old=%q new=%q", transKey, k)
	}
}

func TestReconcilerSkipsFailedDownloadInode(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	r := NewReconciler(syncDir, "", db, time.Minute)

	writeFile(t, filepath.Join(syncDir, "stale.txt"), "old local bytes")
	sid, _ := db.UpsertInode(&cache.Inode{RemotePath: "stale.txt", DisplayName: "stale.txt", Size: 15, SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: sid, Kind: cache.FailureDownload, Permanent: true, Attempts: 1, LastError: "verify failed"})

	writeFile(t, filepath.Join(syncDir, "edited.txt"), "new local bytes")
	eid, _ := db.UpsertInode(&cache.Inode{RemotePath: "edited.txt", DisplayName: "edited.txt", Size: 15, Dirty: true, SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: eid, Kind: cache.FailureDownload, Permanent: false, Attempts: 1, LastError: "timeout"})

	if healed := r.Reconcile(context.Background()); healed != 1 {
		t.Fatalf("healed=%d, want 1 (only the dirty edit)", healed)
	}

	entries, _ := db.DequeueWriteback(100, 0)
	for _, e := range entries {
		if e.InodeID == sid {
			t.Fatalf("stale download-failed inode was queued for upload: %+v", e)
		}
	}
	if len(entries) != 1 || entries[0].InodeID != eid || entries[0].Action != "upload" {
		t.Fatalf("dirty edit not uploaded: %+v", entries)
	}
}

func TestReconcilerSkipsInFlightUpload(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	r := NewReconciler(syncDir, "", db, time.Minute)

	writeFile(t, filepath.Join(syncDir, "big.bin"), "a slow upload spanning a tick")
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "big.bin", DisplayName: "big.bin", Size: 29,
		Dirty: true, SyncStatus: cache.StatusPending,
	})
	db.EnqueueWriteback(id, "upload", "big.bin", "")
	claimed, _ := db.DequeueWriteback(10, 0)
	if len(claimed) != 1 {
		t.Fatalf("fixture: claimed %d rows, want 1", len(claimed))
	}
	inFlightKey := cache.UploadKeyFromExtra(claimed[0].ExtraJSON)

	r.Reconcile(context.Background())

	dupes, _ := db.DequeueWriteback(10, 0)
	if len(dupes) != 0 {
		t.Errorf("reconciler queued %d duplicate upload(s) alongside the in-flight one (key %q vs %q)",
			len(dupes), inFlightKey, cache.UploadKeyFromExtra(dupes[0].ExtraJSON))
	}

	writeFile(t, filepath.Join(syncDir, "orphan.bin"), "queued row lost")
	oid, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "orphan.bin", DisplayName: "orphan.bin", Size: 15,
		Dirty: true, SyncStatus: cache.StatusPending,
	})
	r.Reconcile(context.Background())
	healed, _ := db.DequeueWriteback(10, 0)
	if len(healed) != 1 || healed[0].InodeID != oid || healed[0].Action != "upload" {
		t.Errorf("pending inode with no queue row was not re-queued: %+v", healed)
	}
}

func TestReconcilerHonorsUploadRetryWindow(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	r := NewReconciler(syncDir, "", db, time.Minute)

	writeFile(t, filepath.Join(syncDir, "waiting.txt"), "rate limited")
	wid, _ := db.UpsertInode(&cache.Inode{RemotePath: "waiting.txt", DisplayName: "waiting.txt", Size: 12, Dirty: true, SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{
		InodeID: wid, Kind: cache.FailureUpload, Attempts: maxRetries,
		NextRetryAt: time.Now().Add(5 * time.Minute).Unix(), LastError: "429 daily upload limit",
	})

	writeFile(t, filepath.Join(syncDir, "ready.txt"), "window elapsed")
	rid, _ := db.UpsertInode(&cache.Inode{RemotePath: "ready.txt", DisplayName: "ready.txt", Size: 14, Dirty: true, SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{
		InodeID: rid, Kind: cache.FailureUpload, Attempts: maxRetries,
		NextRetryAt: time.Now().Add(-time.Minute).Unix(), LastError: "502 bad gateway",
	})

	if healed := r.Reconcile(context.Background()); healed != 1 {
		t.Fatalf("healed=%d, want 1 (only the elapsed window)", healed)
	}
	entries, _ := db.DequeueWriteback(100, 0)
	for _, e := range entries {
		if e.InodeID == wid {
			t.Errorf("re-drove an upload still inside its retry window: %+v", e)
		}
	}
	if len(entries) != 1 || entries[0].InodeID != rid {
		t.Errorf("elapsed-window upload not re-queued: %+v", entries)
	}
}

func TestReconcilerIgnoresMetaDir(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	r := NewReconciler(syncDir, "", db, time.Minute)
	if healed := r.Reconcile(context.Background()); healed != 0 {
		t.Fatalf("healed=%d, want 0 (only .pigcloud present)", healed)
	}
	if entries, _ := db.DequeueWriteback(100, 0); len(entries) != 0 {
		t.Fatalf("expected empty queue, got %d entries", len(entries))
	}
}
