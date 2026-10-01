package cache

import (
	"testing"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestUpsertInodePreservesLocalHash(t *testing.T) {
	db := openTestDB(t)

	id, err := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, LocalHash: "abc123"})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if _, err := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 4}); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	in, _ := db.GetInode(id)
	if in == nil || in.LocalHash != "abc123" {
		t.Fatalf("listing rebuild erased the digest: %+v", in)
	}

	if _, err := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 4, LocalHash: "def456"}); err != nil {
		t.Fatalf("upsert with digest: %v", err)
	}
	if in, _ := db.GetInode(id); in == nil || in.LocalHash != "def456" {
		t.Fatalf("an explicit digest did not overwrite: %+v", in)
	}
}

func TestInvalidateCacheClearsLocalHash(t *testing.T) {
	db := openTestDB(t)
	id, _ := db.UpsertInode(&Inode{
		RemotePath: "a.txt", DisplayName: "a.txt", Size: 3,
		Cached: true, ContentHash: "blob", LocalHash: "abc123", LocalMtime: 999,
	})

	if err := db.InvalidateCache(id); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	in, _ := db.GetInode(id)
	if in == nil || in.LocalHash != "" || in.LocalMtime != 0 || in.ContentHash != "" || in.Cached {
		t.Fatalf("invalidate left stale state: %+v", in)
	}
}

func TestSetLocalContentRoundTrip(t *testing.T) {
	db := openTestDB(t)
	id, _ := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt"})

	db.SetLocalContent(id, "deadbeef", 1700000000)
	in, _ := db.GetInode(id)
	if in == nil || in.LocalHash != "deadbeef" || in.LocalMtime != 1700000000 {
		t.Fatalf("digest pair not stored: %+v", in)
	}
	db.SetLocalContent(id, "", 1700000000)
	if in, _ := db.GetInode(id); in == nil || in.LocalHash != "" || in.LocalMtime != 0 {
		t.Fatalf("digest pair not cleared together: %+v", in)
	}
}

func TestLocalMtimeDoesNotTouchInodeMtime(t *testing.T) {
	db := openTestDB(t)
	id, _ := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Mtime: 111})

	db.SetLocalContent(id, "abc", 222)
	in, _ := db.GetInode(id)
	if in == nil || in.Mtime != 111 {
		t.Fatalf("remote timestamp overwritten by a local one: %+v", in)
	}
	if in.LocalMtime != 222 {
		t.Fatalf("local timestamp not recorded: %+v", in)
	}
}

func TestClearFailedTransfers(t *testing.T) {
	db := openTestDB(t)

	failedID, _ := db.UpsertInode(&Inode{RemotePath: "up.txt", DisplayName: "up.txt", Dirty: true, SyncStatus: StatusFailed})
	db.RecordSyncFailure(&SyncFailure{InodeID: failedID, Kind: FailureUpload, Permanent: true, Attempts: 3, LastError: "over quota"})
	db.EnqueueWriteback(failedID, "upload", "up.txt", "")
	ents, _ := db.DequeueWriteback(10, 0)
	db.UpdateWriteback(ents[0].ID, "failed", "over quota", 3)

	dlID, _ := db.UpsertInode(&Inode{RemotePath: "down.txt", DisplayName: "down.txt", SyncStatus: StatusFailed})
	db.RecordSyncFailure(&SyncFailure{InodeID: dlID, Kind: FailureDownload, Permanent: true, Attempts: 1, LastError: "owner_signing_pk_untrusted"})

	rejID, _ := db.UpsertInode(&Inode{RemotePath: "bad.exe", DisplayName: "bad.exe", SyncStatus: StatusRejected})
	db.RecordSyncFailure(&SyncFailure{InodeID: rejID, Kind: FailureUpload, Permanent: true, Attempts: 1})
	conID, _ := db.UpsertInode(&Inode{RemotePath: "both.txt", DisplayName: "both.txt", SyncStatus: StatusConflict})
	db.RecordSyncFailure(&SyncFailure{InodeID: conID, Kind: FailureUpload, Permanent: true, Attempts: 1})

	cleared, err := ClearFailedTransfers(db, "")
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if len(cleared) != 2 {
		t.Fatalf("cleared %d inode(s), want 2 (the two failed ones)", len(cleared))
	}
	if f, _ := db.GetSyncFailure(failedID, FailureUpload); f != nil {
		t.Errorf("upload failure survived: %+v", f)
	}
	if f, _ := db.GetSyncFailure(dlID, FailureDownload); f != nil {
		t.Errorf("download failure survived: %+v", f)
	}
	if n, _ := db.FailedWritebackCount(); n != 0 {
		t.Errorf("terminal writeback rows left: %d", n)
	}
	if f, _ := db.GetSyncFailure(conID, FailureUpload); f == nil {
		t.Error("a conflict's failure row was cleared; resolve owns that state")
	}
	if f, _ := db.GetSyncFailure(rejID, FailureUpload); f == nil {
		t.Error("a rejected inode's failure row was cleared; clean owns that state")
	}
	if in, _ := db.GetInode(rejID); in == nil || in.SyncStatus != StatusRejected {
		t.Errorf("rejected inode disturbed: %+v", in)
	}
}

func TestClearFailedTransfersByPath(t *testing.T) {
	db := openTestDB(t)
	aID, _ := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", SyncStatus: StatusFailed})
	db.RecordSyncFailure(&SyncFailure{InodeID: aID, Kind: FailureDownload, Permanent: true})
	bID, _ := db.UpsertInode(&Inode{RemotePath: "b.txt", DisplayName: "b.txt", SyncStatus: StatusFailed})
	db.RecordSyncFailure(&SyncFailure{InodeID: bID, Kind: FailureDownload, Permanent: true})

	cleared, err := ClearFailedTransfers(db, "a.txt")
	if err != nil || len(cleared) != 1 || cleared[0].ID != aID {
		t.Fatalf("path-scoped clear = %+v (err %v)", cleared, err)
	}
	if f, _ := db.GetSyncFailure(bID, FailureDownload); f == nil {
		t.Error("a path-scoped retry cleared an unrelated file")
	}

	if cleared, err := ClearFailedTransfers(db, "missing.txt"); err != nil || len(cleared) != 0 {
		t.Fatalf("unknown path = %+v (err %v)", cleared, err)
	}
}
