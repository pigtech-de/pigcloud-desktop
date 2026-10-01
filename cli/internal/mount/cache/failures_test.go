package cache

import (
	"path/filepath"
	"testing"
)

func TestSyncFailureRoundTrip(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if f, err := db.GetSyncFailure(1, FailureDownload); err != nil || f != nil {
		t.Fatalf("expected no failure, got %+v err %v", f, err)
	}

	if err := db.RecordSyncFailure(&SyncFailure{
		InodeID: 1, Kind: FailureDownload, Attempts: 2, NextRetryAt: 12345, LastError: "boom",
	}); err != nil {
		t.Fatalf("RecordSyncFailure: %v", err)
	}
	f, err := db.GetSyncFailure(1, FailureDownload)
	if err != nil || f == nil {
		t.Fatalf("GetSyncFailure: %+v err %v", f, err)
	}
	if f.Permanent || f.Attempts != 2 || f.NextRetryAt != 12345 || f.LastError != "boom" {
		t.Fatalf("round-trip mismatch: %+v", f)
	}

	if err := db.RecordSyncFailure(&SyncFailure{
		InodeID: 1, Kind: FailureDownload, Permanent: true, Attempts: 3, LastError: "too big",
	}); err != nil {
		t.Fatalf("re-record: %v", err)
	}
	f, _ = db.GetSyncFailure(1, FailureDownload)
	if !f.Permanent || f.Attempts != 3 {
		t.Fatalf("upsert did not update: %+v", f)
	}

	db.RecordSyncFailure(&SyncFailure{InodeID: 1, Kind: FailureUpload, Attempts: 1})
	if f, _ := db.GetSyncFailure(1, FailureUpload); f == nil || f.Attempts != 1 {
		t.Fatalf("upload-kind row missing: %+v", f)
	}

	if err := db.ClearSyncFailure(1, FailureDownload); err != nil {
		t.Fatalf("ClearSyncFailure: %v", err)
	}
	if f, _ := db.GetSyncFailure(1, FailureDownload); f != nil {
		t.Fatal("download failure not cleared")
	}
	if f, _ := db.GetSyncFailure(1, FailureUpload); f == nil {
		t.Fatal("upload failure cleared by the wrong key")
	}

	db.RecordSyncFailure(&SyncFailure{InodeID: 1, Kind: FailureDownload, Attempts: 1})
	if err := db.DeleteSyncFailures(1); err != nil {
		t.Fatalf("DeleteSyncFailures: %v", err)
	}
	if f, _ := db.GetSyncFailure(1, FailureDownload); f != nil {
		t.Fatal("download failure survived DeleteSyncFailures")
	}
	if f, _ := db.GetSyncFailure(1, FailureUpload); f != nil {
		t.Fatal("upload failure survived DeleteSyncFailures")
	}
}

func TestUploadExtraRoundTrip(t *testing.T) {
	if MarshalUploadExtra("") != "" {
		t.Fatal("empty key must yield empty extra so EnqueueWriteback mints one")
	}
	extra := MarshalUploadExtra("key-abc")
	if got := UploadKeyFromExtra(extra); got != "key-abc" {
		t.Fatalf("round-trip: got %q", got)
	}
	if got := UploadKeyFromExtra(""); got != "" {
		t.Fatalf("empty extra: got %q", got)
	}
	if got := UploadKeyFromExtra(`{"target":"/x"}`); got != "" {
		t.Fatalf("rename extra leaked a key: %q", got)
	}
}

func claimOne(t *testing.T, db *DB) *WritebackEntry {
	t.Helper()
	entries, err := db.DequeueWriteback(100, 0)
	if err != nil {
		t.Fatalf("DequeueWriteback: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 claimable entry, got %d", len(entries))
	}
	return entries[0]
}

func TestUploadIdempotencyKeyRowScoped(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "c"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if err := db.EnqueueWriteback(1, "upload", "a.txt", ""); err != nil {
		t.Fatalf("EnqueueWriteback: %v", err)
	}
	e := claimOne(t, db)
	key := UploadKeyFromExtra(e.ExtraJSON)
	if key == "" {
		t.Fatal("enqueue did not mint an idempotency key")
	}

	if err := db.UpdateWriteback(e.ID, "pending", "timeout", 1); err != nil {
		t.Fatalf("UpdateWriteback: %v", err)
	}
	e2 := claimOne(t, db)
	if e2.ID != e.ID || UploadKeyFromExtra(e2.ExtraJSON) != key || e2.Attempts != 1 {
		t.Fatalf("retry lost row identity or key: %+v", e2)
	}

	if _, err := db.RequeueInProgress(); err != nil {
		t.Fatalf("RequeueInProgress: %v", err)
	}
	e3 := claimOne(t, db)
	if e3.ID != e.ID || UploadKeyFromExtra(e3.ExtraJSON) != key {
		t.Fatalf("RequeueInProgress lost row identity or key: %+v", e3)
	}
	db.UpdateWriteback(e3.ID, "pending", "", e3.Attempts)

	if err := db.EnqueueWriteback(1, "upload", "a.txt", ""); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	e4 := claimOne(t, db)
	if e4.ID == e.ID {
		t.Fatal("collapse did not replace the row")
	}
	if k4 := UploadKeyFromExtra(e4.ExtraJSON); k4 == "" || k4 == key {
		t.Fatalf("new enqueue must mint a fresh key: old=%q new=%q", key, k4)
	}
	db.DeleteWriteback(e4.ID)

	db.EnqueueWriteback(2, "upload", "b.txt", "")
	eB := claimOne(t, db)
	if kB := UploadKeyFromExtra(eB.ExtraJSON); kB == "" || kB == key {
		t.Fatal("distinct inode did not get its own key")
	}
	db.EnqueueWriteback(3, "upload", "c.txt", MarshalUploadExtra("preseed"))
	eC := claimOne(t, db)
	if UploadKeyFromExtra(eC.ExtraJSON) != "preseed" {
		t.Fatal("caller-supplied key was clobbered")
	}
}

func TestFailedDownloadCount(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	must := func(f *SyncFailure) {
		t.Helper()
		if err := db.RecordSyncFailure(f); err != nil {
			t.Fatalf("RecordSyncFailure: %v", err)
		}
	}
	count := func() int {
		t.Helper()
		n, err := db.FailedDownloadCount()
		if err != nil {
			t.Fatalf("FailedDownloadCount: %v", err)
		}
		return n
	}

	must(&SyncFailure{InodeID: 1, Kind: FailureDownload, Attempts: 1})
	if got := count(); got != 0 {
		t.Fatalf("fresh transient counted as failed: %d", got)
	}

	must(&SyncFailure{InodeID: 1, Kind: FailureDownload, Attempts: StalledDownloadAttempts})
	if got := count(); got != 1 {
		t.Fatalf("stalled download not counted: %d", got)
	}

	must(&SyncFailure{InodeID: 2, Kind: FailureDownload, Permanent: true, Attempts: 1})
	if got := count(); got != 2 {
		t.Fatalf("permanent download not counted: %d", got)
	}

	must(&SyncFailure{InodeID: 3, Kind: FailureUpload, Permanent: true, Attempts: 9})
	if got := count(); got != 2 {
		t.Fatalf("upload failure leaked into download count: %d", got)
	}
}

func TestDeleteFailedUploadWritebacksScoped(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	db.EnqueueWriteback(1, "upload", "a.txt", "")
	db.EnqueueWriteback(1, "delete", "old.txt", "")
	db.EnqueueWriteback(2, "upload", "b.txt", "")
	entries, _ := db.DequeueWriteback(100, 0)
	for _, e := range entries {
		db.UpdateWriteback(e.ID, "failed", "boom", 3)
	}

	if err := db.DeleteFailedUploadWritebacks(1); err != nil {
		t.Fatalf("DeleteFailedUploadWritebacks: %v", err)
	}
	failed, _ := db.FailedWritebackCount()
	if failed != 2 {
		t.Fatalf("want 2 surviving failed rows (inode 1 delete + inode 2 upload), got %d", failed)
	}
}

func TestHasActiveWritebackKeysOnActionNotFailureKind(t *testing.T) {
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	const inodeID = 1
	db.EnqueueWriteback(inodeID, "upload", "a.txt", "")
	db.RecordSyncFailure(&SyncFailure{InodeID: inodeID, Kind: FailureDownload, Attempts: 1, LastError: "timeout"})

	if active, err := db.HasActiveWriteback(inodeID, "upload"); err != nil || !active {
		t.Errorf("queued upload not seen: active=%v err=%v", active, err)
	}
	if active, _ := db.HasActiveWriteback(inodeID, FailureDownload); active {
		t.Error("a sync_failures kind matched a writeback_queue action")
	}
	if active, _ := db.HasActiveWriteback(inodeID, "mkdir"); active {
		t.Error("an unrelated action matched the queued upload")
	}

	entries, _ := db.DequeueWriteback(10, 0)
	if active, _ := db.HasActiveWriteback(inodeID, "upload"); !active {
		t.Error("claimed (in_progress) row not counted as active")
	}
	db.UpdateWriteback(entries[0].ID, "failed", "boom", 3)
	if active, _ := db.HasActiveWriteback(inodeID, "upload"); active {
		t.Error("terminal (failed) row still counted as active")
	}
}
