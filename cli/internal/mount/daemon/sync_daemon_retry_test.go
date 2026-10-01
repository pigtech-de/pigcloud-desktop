package daemon

import (
	"strings"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/mount"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/syncer"
	"pigcloud/internal/mount/vfs"
)

func retryFixture(t *testing.T) (*SyncDaemon, *cache.DB) {
	t.Helper()
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	syncDir := t.TempDir()
	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	dl := syncer.NewDownloader(syncDir, "", v, nil, db, &sync.Map{})
	wb := syncer.NewWritebackProcessor(v, nil, db, nil, syncDir)
	return &SyncDaemon{token: "tok", cacheDB: db, vfs: v, downloader: dl, writeback: wb}, db
}

func TestSyncRetryRequeuesLatchedUpload(t *testing.T) {
	sd, db := retryFixture(t)

	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "report.pdf", DisplayName: "report.pdf", Size: 9,
		Mtime: time.Now().Unix(), Dirty: true, SyncStatus: cache.StatusFailed,
		StatusReason: "upload: over quota",
	})
	db.RecordSyncFailure(&cache.SyncFailure{
		InodeID: id, Kind: cache.FailureUpload, Permanent: true, Attempts: 3, LastError: "over quota",
	})

	n, err := sd.retryFailed("")
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n != 1 {
		t.Fatalf("retried %d, want 1", n)
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureUpload); f != nil {
		t.Errorf("permanent upload failure survived the retry: %+v", f)
	}
	in, _ := db.GetInode(id)
	if in == nil || in.SyncStatus != cache.StatusPending {
		t.Errorf("inode not reset to pending: %+v", in)
	}
	entries, _ := db.DequeueWriteback(10, 0)
	if len(entries) != 1 || entries[0].InodeID != id || entries[0].Action != "upload" {
		t.Fatalf("upload not re-queued: %+v", entries)
	}
}

func TestSyncRetryReopensFailedDownloadWithoutUploading(t *testing.T) {
	sd, db := retryFixture(t)

	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "peer.pdf", DisplayName: "peer.pdf", Size: 9,
		Mtime: time.Now().Unix(), SyncStatus: cache.StatusFailed,
		StatusReason: "verify: owner_signing_pk_untrusted",
	})
	db.RecordSyncFailure(&cache.SyncFailure{
		InodeID: id, Kind: cache.FailureDownload, Permanent: true, Attempts: 1,
		LastError: "owner_signing_pk_untrusted",
	})

	if n, err := sd.retryFailed(""); err != nil || n != 1 {
		t.Fatalf("retry = %d (err %v), want 1", n, err)
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
		t.Errorf("download failure survived: %+v", f)
	}
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("a failed download queued %d upload(s)", n)
	}
	if n, _ := db.FailedDownloadCount(); n != 0 {
		t.Errorf("mn status still counts %d stalled download(s)", n)
	}
}

func TestSyncRetryLeavesConflictsAndRejectsAlone(t *testing.T) {
	sd, db := retryFixture(t)

	conID, _ := db.UpsertInode(&cache.Inode{RemotePath: "both.txt", DisplayName: "both.txt", Dirty: true, SyncStatus: cache.StatusConflict})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: conID, Kind: cache.FailureUpload, Permanent: true})
	rejID, _ := db.UpsertInode(&cache.Inode{RemotePath: "bad.exe", DisplayName: "bad.exe", SyncStatus: cache.StatusRejected})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: rejID, Kind: cache.FailureUpload, Permanent: true})

	if n, err := sd.retryFailed(""); err != nil || n != 0 {
		t.Fatalf("retry = %d (err %v), want 0", n, err)
	}
	if in, _ := db.GetInode(conID); in == nil || in.SyncStatus != cache.StatusConflict {
		t.Errorf("conflict disturbed: %+v", in)
	}
	if in, _ := db.GetInode(rejID); in == nil || in.SyncStatus != cache.StatusRejected {
		t.Errorf("rejected inode disturbed: %+v", in)
	}
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("retry queued %d upload(s) for non-failed inodes", n)
	}
}

func TestRetryIPCAction(t *testing.T) {
	sd, db := retryFixture(t)
	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Dirty: true, SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: id, Kind: cache.FailureUpload, Permanent: true})

	resp := roundTripSync(t, sd, mount.DaemonRequest{Token: "tok", Action: "retry"})
	if !resp.OK || resp.Retried != 1 {
		t.Fatalf("retry over IPC: %+v", resp)
	}

	if !isMutatingIPC("retry") {
		t.Error("retry is not gated as a mutating action")
	}
	sd.gate.close()
	if resp := roundTripSync(t, sd, mount.DaemonRequest{Token: "tok", Action: "retry"}); resp.Error != "shutting down" {
		t.Errorf("retry during shutdown: %+v, want shutting-down rejection", resp)
	}
}

func TestVirtualRetryReachesABarrieredFailure(t *testing.T) {
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	d := &Daemon{token: "tok", cacheDB: db, vfs: v}

	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "peer.pdf", DisplayName: "peer.pdf"})

	for _, path := range []string{"", "peer.pdf"} {
		if err := db.RecordSyncFailure(&cache.SyncFailure{
			InodeID: id, Kind: cache.FailureDownload, Permanent: true, LastError: "decrypt: bad tag",
		}); err != nil {
			t.Fatal(err)
		}
		n, err := d.retryFailed(path)
		if err != nil {
			t.Fatalf("retry(%q): %v", path, err)
		}
		if n != 1 {
			t.Errorf("retry(%q) cleared %d, want 1: the barrier it must clear is unreachable", path, n)
		}
		if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
			t.Errorf("retry(%q) left the barrier in place: %+v", path, f)
		}
	}
}

func TestSyncRetryReachesAStalledTransientDownload(t *testing.T) {
	sd, db := retryFixture(t)
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "slow.bin", DisplayName: "slow.bin", SyncStatus: cache.StatusSynced,
	})
	db.RecordSyncFailure(&cache.SyncFailure{
		InodeID: id, Kind: cache.FailureDownload, Attempts: 9,
		NextRetryAt: time.Now().Add(time.Hour).Unix(), LastError: "connection reset",
	})
	if n, _ := db.FailedDownloadCount(); n != 1 {
		t.Fatalf("fixture: mn status reports %d stalled downloads, want 1", n)
	}

	if n, err := sd.retryFailed(""); err != nil || n != 1 {
		t.Fatalf("retry = %d (err %v), want 1", n, err)
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
		t.Errorf("stalled download still parked behind its backoff: %+v", f)
	}
}

func TestReadOnlyMountNeitherQueuesNorFlushes(t *testing.T) {
	sd, db := retryFixture(t)
	sd.vfs.SetReadOnly(true)

	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "a.txt", DisplayName: "a.txt", Dirty: true, SyncStatus: cache.StatusFailed,
	})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: id, Kind: cache.FailureUpload, Permanent: true})

	if _, err := sd.retryFailed(""); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("retry queued %d upload(s) on a read-only mount", n)
	}

	sd.vfs.SetReadOnly(false)
	db.EnqueueWriteback(id, "upload", "a.txt", "")
	sd.vfs.SetReadOnly(true)
	if _, err := sd.writeback.FlushAll(time.Second); err == nil {
		t.Error("FlushAll accepted on a read-only mount; shutdown calls it unguarded")
	}
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Errorf("the refused flush consumed the queue: %d row(s) left, want 1", n)
	}
}

func TestResolveLocalOnReadOnlyMountLeavesTheConflictIntact(t *testing.T) {
	sd, db, id, _ := resolveFixture(t)
	sd.vfs.SetReadOnly(true)

	err := sd.resolveConflict("notes.txt", "local")
	if err == nil {
		t.Fatal("resolve -k local accepted on a read-only mount")
	}
	if !strings.Contains(err.Error(), "read-only") {
		t.Errorf("refusal does not name the cause: %v", err)
	}

	in, _ := db.GetInodeByPath("notes.txt")
	if in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("the refusal destroyed the conflict marker: %+v", in)
	}
	entries, _ := db.DequeueWriteback(10, 0)
	if len(entries) != 1 || entries[0].InodeID != id {
		t.Errorf("held upload dropped by a refused resolve: %+v", entries)
	}
}

func TestFlushRefusedOnReadOnlyMount(t *testing.T) {
	sd, db := retryFixture(t)
	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Dirty: true, SyncStatus: cache.StatusPending})
	db.EnqueueWriteback(id, "upload", "a.txt", "")

	sd.vfs.SetReadOnly(true)
	resp := roundTripSync(t, sd, mount.DaemonRequest{Token: "tok", Action: "flush"})
	if resp.OK {
		t.Fatalf("flush accepted on a read-only mount: %+v", resp)
	}
	if !strings.Contains(resp.Error, "read-only") {
		t.Errorf("flush refusal does not name the cause: %q", resp.Error)
	}
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Errorf("the refused flush still consumed the queue: %d row(s) left, want 1", n)
	}
}

func TestVirtualRetryClearsDownloadMemory(t *testing.T) {
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	d := &Daemon{token: "tok", cacheDB: db, vfs: v}

	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "peer.pdf", DisplayName: "peer.pdf", SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: id, Kind: cache.FailureDownload, Permanent: true, LastError: "verify"})

	resp := roundTripVirtual(t, d, mount.DaemonRequest{Token: "tok", Action: "retry"})
	if !resp.OK || resp.Retried != 1 {
		t.Fatalf("virtual retry: %+v", resp)
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
		t.Errorf("virtual retry left the failure row: %+v", f)
	}
}
