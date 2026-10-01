package syncer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func newDownloader(t *testing.T, remotePath string) (*Downloader, *cache.DB, string) {
	t.Helper()
	return newDownloaderMode(t, remotePath, false)
}

func newDownloaderMode(t *testing.T, remotePath string, readOnly bool) (*Downloader, *cache.DB, string) {
	t.Helper()
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	v := vfs.New(remotePath, db, nil, nil, nil, nil, nil, nil, nil, nil)
	v.SetReadOnly(readOnly)
	return NewDownloader(syncDir, remotePath, v, nil, db, &sync.Map{}), db, syncDir
}

func TestCleanupStaleEntries(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")

	fid, _ := db.UpsertInode(&cache.Inode{RemotePath: "f.txt", DisplayName: "f.txt", SyncStatus: cache.StatusFailed})
	db.EnqueueWriteback(fid, "upload", "f.txt", "")
	ents, _ := db.DequeueWriteback(10, 0)
	db.UpdateWriteback(ents[0].ID, "failed", "boom", maxRetries)

	gid, _ := db.UpsertInode(&cache.Inode{RemotePath: "gone.txt", DisplayName: "gone.txt", SyncStatus: cache.StatusFailed})
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: gid, Kind: cache.FailureUpload, Attempts: 1})

	db.UpsertInode(&cache.Inode{RemotePath: "bad.exe", DisplayName: "bad.exe", SyncStatus: cache.StatusRejected})

	writeFile(t, filepath.Join(syncDir, "here.txt"), "still here")
	hid, _ := db.UpsertInode(&cache.Inode{RemotePath: "here.txt", DisplayName: "here.txt", Size: 9, SyncStatus: cache.StatusFailed})

	cleaned := d.cleanupStaleEntries()
	if cleaned < 2 {
		t.Errorf("cleaned = %d, want >= 2 (gone + bad)", cleaned)
	}

	if failed, _ := db.FailedWritebackCount(); failed != 0 {
		t.Errorf("failed writebacks not purged: %d remain", failed)
	}
	if in, _ := db.GetInodeByPath("gone.txt"); in != nil {
		t.Error("failed inode with missing local file not cleaned")
	}
	if in, _ := db.GetInodeByPath("bad.exe"); in != nil {
		t.Error("rejected inode with missing local file not cleaned")
	}
	if in, _ := db.GetInodeByPath("here.txt"); in == nil || in.ID != hid {
		t.Error("failed inode with present local file was wrongly cleaned")
	}
}

func TestScanLocalNewFiles(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")

	writeFile(t, filepath.Join(syncDir, "new.txt"), "fresh")
	if err := os.Mkdir(filepath.Join(syncDir, "subdir"), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(syncDir, "bad@name.txt"), "rejected by name regex")
	writeFile(t, filepath.Join(syncDir, "tracked.txt"), "already known")
	db.UpsertInode(&cache.Inode{RemotePath: "tracked.txt", DisplayName: "tracked.txt", Size: 12, SyncStatus: cache.StatusSynced})

	queued := d.scanLocalNewFiles()
	if queued != 2 {
		t.Errorf("queued = %d, want 2 (new.txt upload + subdir mkdir)", queued)
	}

	actions := map[string]string{}
	ents, _ := db.DequeueWriteback(100, 0)
	for _, e := range ents {
		actions[e.RemotePath] = e.Action
	}
	if actions["new.txt"] != "upload" {
		t.Errorf("new.txt action = %q, want upload", actions["new.txt"])
	}
	if actions["subdir"] != "mkdir" {
		t.Errorf("subdir action = %q, want mkdir", actions["subdir"])
	}
	if _, ok := actions["bad@name.txt"]; ok {
		t.Error("rejected file was queued for upload")
	}
	if _, ok := actions["tracked.txt"]; ok {
		t.Error("already-tracked file was re-queued")
	}
	if in, _ := db.GetInodeByPath("bad@name.txt"); in == nil || in.SyncStatus != cache.StatusRejected {
		t.Errorf("rejected file not tracked as rejected inode: %+v", in)
	}
}

func TestEnqueueLocalUpload(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")

	okPath := filepath.Join(syncDir, "edit.txt")
	writeFile(t, okPath, "edited offline")
	info, _ := os.Stat(okPath)
	node := vfs.NewFileNode("edit.txt", "edit.txt", 0, time.Now(), nil)
	d.enqueueLocalUpload(node, okPath, info)

	if !node.Dirty || node.Cached {
		t.Errorf("node not marked dirty+uncached: dirty=%v cached=%v", node.Dirty, node.Cached)
	}
	in, _ := db.GetInodeByPath("edit.txt")
	if in == nil || in.SyncStatus != cache.StatusPending || !in.Dirty {
		t.Errorf("edit not tracked pending+dirty: %+v", in)
	}
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Errorf("pending writebacks = %d, want 1", n)
	}

	badPath := filepath.Join(syncDir, "bad@edit.txt")
	writeFile(t, badPath, "unsupported name")
	badInfo, _ := os.Stat(badPath)
	badNode := vfs.NewFileNode("bad@edit.txt", "bad@edit.txt", 0, time.Now(), nil)
	d.enqueueLocalUpload(badNode, badPath, badInfo)

	if in, _ := db.GetInodeByPath("bad@edit.txt"); in == nil || in.SyncStatus != cache.StatusRejected {
		t.Errorf("rejected edit not tracked rejected: %+v", in)
	}
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Errorf("rejected edit leaked a writeback: pending=%d, want 1", n)
	}
}

func TestRecordDownloadFailure(t *testing.T) {
	d, db, _ := newDownloader(t, "")

	permNode := &vfs.Node{ID: mustInode(t, db, "perm.txt"), RemotePath: "perm.txt"}
	d.recordDownloadFailure(permNode, permanent(errors.New("verify failed")))
	f, _ := db.GetSyncFailure(permNode.ID, cache.FailureDownload)
	if f == nil || !f.Permanent {
		t.Fatalf("permanent failure not recorded: %+v", f)
	}
	if in, _ := db.GetInode(permNode.ID); in == nil || in.SyncStatus != cache.StatusFailed {
		t.Errorf("permanent failure did not mark inode failed: %+v", in)
	}
	if d.downloadDue(permNode.ID) {
		t.Error("permanently-failed node reported due for retry")
	}

	transNode := &vfs.Node{ID: mustInode(t, db, "trans.txt"), RemotePath: "trans.txt"}
	d.recordDownloadFailure(transNode, errors.New("timeout"))
	f1, _ := db.GetSyncFailure(transNode.ID, cache.FailureDownload)
	if f1 == nil || f1.Permanent || f1.Attempts != 1 || f1.NextRetryAt <= time.Now().Unix() {
		t.Fatalf("transient failure recorded wrong: %+v", f1)
	}
	if d.downloadDue(transNode.ID) {
		t.Error("transient node inside its backoff window reported due")
	}

	d.recordDownloadFailure(transNode, errors.New("timeout again"))
	if f2, _ := db.GetSyncFailure(transNode.ID, cache.FailureDownload); f2 == nil || f2.Attempts != 2 {
		t.Errorf("second transient failure did not increment attempts: %+v", f2)
	}

	cancelNode := &vfs.Node{ID: mustInode(t, db, "cancel.txt"), RemotePath: "cancel.txt"}
	d.recordDownloadFailure(cancelNode, context.Canceled)
	if f, _ := db.GetSyncFailure(cancelNode.ID, cache.FailureDownload); f != nil {
		t.Errorf("cancellation recorded as a failure: %+v", f)
	}

	for range 2 {
		d.recordDownloadFailure(transNode, errors.New("still timing out"))
	}
	if n, _ := db.FailedDownloadCount(); n != 2 {
		t.Errorf("FailedDownloadCount = %d, want 2 (perm + stalled transient)", n)
	}
}

func TestDownloadDueNoRecord(t *testing.T) {
	d, db, _ := newDownloader(t, "")
	id := mustInode(t, db, "clean.txt")
	if !d.downloadDue(id) {
		t.Error("node with no failure record reported not due")
	}
	if !d.downloadDue(0) {
		t.Error("zero id reported not due")
	}
}

func TestWalkForDownloadsClearsFailureFromLocalCopy(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")

	body := "the copy the user fetched from the web app"
	writeFile(t, filepath.Join(syncDir, "shared.pdf"), body)
	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "shared.pdf", DisplayName: "shared.pdf", Size: int64(len(body)), Etag: "version-a"})
	db.SetLocalContent(id, digestOf(body), 0)
	node := vfs.NewFileNode("shared.pdf", "shared.pdf", int64(len(body)), time.Now(), nil)
	node.ID = id
	node.Etag = "version-a"

	d.recordDownloadFailure(node, permanent(errors.New(
		`verify shared.pdf: foreign_signer_unsupported: file signed by "bob", verify it in the web app`)))
	if in, _ := db.GetInode(id); in == nil || in.SyncStatus != cache.StatusFailed {
		t.Fatalf("fixture: inode not marked failed: %+v", in)
	}

	var wg sync.WaitGroup
	d.walkForDownloads(context.Background(), node, &wg)
	wg.Wait()

	if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
		t.Errorf("local copy is in place but the download failure survives: %+v", f)
	}
	if !node.Cached {
		t.Error("node not marked cached from the local copy")
	}
	if in, _ := db.GetInode(id); in == nil || in.SyncStatus != cache.StatusSynced {
		t.Errorf("inode still not synced: %+v", in)
	}
	if n, _ := db.FailedDownloadCount(); n != 0 {
		t.Errorf("mn status still reports %d failed download(s)", n)
	}
}

func TestWalkForDownloadsStillHoldsPermanentFailures(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")

	writeFile(t, filepath.Join(syncDir, "huge.bin"), "a stale local stub of the wrong size")
	oversize := int64(api.MaxInMemoryDownloadSize) + 1
	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "huge.bin", DisplayName: "huge.bin", Size: oversize})
	db.SetLocalContent(id, digestOf("a stale local stub of the wrong size"), 0)
	db.InvalidateCache(id)
	node := vfs.NewFileNode("huge.bin", "huge.bin", oversize, time.Now(), nil)
	node.ID = id

	d.recordDownloadFailure(node, permanent(errors.New("verify huge.bin: owner_signing_pk_untrusted")))

	var wg sync.WaitGroup
	d.walkForDownloads(context.Background(), node, &wg)
	wg.Wait()

	f, _ := db.GetSyncFailure(id, cache.FailureDownload)
	if f == nil || !f.Permanent {
		t.Fatalf("permanent failure lost: %+v", f)
	}
	if f.Attempts != 1 {
		t.Errorf("attempts = %d, want 1: the gate let a permanently-failed node re-dispatch", f.Attempts)
	}
	if node.Cached {
		t.Error("size-mismatched local stub was accepted as the cached copy")
	}
}

func TestWalkAndSyncClearsFailureOnMatchingLocalCopy(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")

	body := "already here from a previous session"
	writeFile(t, filepath.Join(syncDir, "doc.txt"), body)
	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "doc.txt", DisplayName: "doc.txt", Size: int64(len(body))})
	node := vfs.NewFileNode("doc.txt", "doc.txt", int64(len(body)), time.Now(), nil)
	node.ID = id
	d.recordDownloadFailure(node, errors.New("connection reset"))

	var downloaded, skipped int64
	var wg sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &wg); err != nil {
		t.Fatalf("walkAndSync: %v", err)
	}
	wg.Wait()

	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (local copy matches)", skipped)
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
		t.Errorf("initial sync accepted the local copy but kept the failure: %+v", f)
	}
}

func TestCommitDownloadReleasesSupersededBlob(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	d.SetStore(store)

	blob, err := store.Put([]byte("the locally edited copy"))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "doc.txt", DisplayName: "doc.txt", Size: 23,
		Cached: true, ContentHash: blob, SyncStatus: cache.StatusSynced,
	})

	d.commitDownload(id, 42, "digest-of-the-downloaded-plaintext", 1700000000)

	in, _ := db.GetInode(id)
	if in == nil || in.ContentHash != "" {
		t.Fatalf("commit did not clear content_hash: %+v", in)
	}
	if store.Has(blob) {
		t.Errorf("blob %s stranded: nothing references it and only a daemon restart reclaims it", blob)
	}
}

func TestCommitDownloadKeepsBlobSharedWithAnotherInode(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	d.SetStore(store)

	blob, err := store.Put([]byte("same bytes in two places"))
	if err != nil {
		t.Fatal(err)
	}
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "a.txt", DisplayName: "a.txt", Size: 24,
		Cached: true, ContentHash: blob, SyncStatus: cache.StatusSynced,
	})
	db.UpsertInode(&cache.Inode{
		RemotePath: "b.txt", DisplayName: "b.txt", Size: 24,
		Cached: true, ContentHash: blob, SyncStatus: cache.StatusSynced,
	})

	d.commitDownload(id, 42, "digest-of-the-downloaded-plaintext", 1700000000)

	if !store.Has(blob) {
		t.Errorf("blob %s still referenced by b.txt was released", blob)
	}
}

func TestRemoveLocal(t *testing.T) {
	d, _, syncDir := newDownloader(t, "")
	var events []string
	d.SetActivityCallback(func(path, direction string, bytes int64, err error) {
		events = append(events, direction+":"+path)
	})

	target := filepath.Join(syncDir, "doc.txt")
	writeFile(t, target, "remote deleted me")

	d.RemoveLocal("doc.txt")

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("file not moved out of the sync tree (stat err = %v)", err)
	}
	trashed := filepath.Join(syncDir, ".pigcloud", "trash", "doc.txt")
	if _, err := os.Stat(trashed); err != nil {
		t.Errorf("file not moved into trash: %v", err)
	}
	if len(events) != 1 || events[0] != "delete:doc.txt" {
		t.Errorf("activity events = %v, want [delete:doc.txt]", events)
	}
}

func TestPathMapping(t *testing.T) {
	syncDir := t.TempDir()
	d := NewDownloader(syncDir, "Photos", nil, nil, nil, &sync.Map{})

	if got := d.toLocalPath("Photos/2024/pic.jpg"); got != filepath.Join(syncDir, "2024", "pic.jpg") {
		t.Errorf("toLocalPath = %q", got)
	}
	if got := d.pathToRemote(filepath.Join(syncDir, "2024", "pic.jpg")); got != "Photos/2024/pic.jpg" {
		t.Errorf("pathToRemote = %q", got)
	}
	if _, ok := d.localPathWithin("Photos/ok.txt"); !ok {
		t.Error("in-tree path rejected")
	}

	root := NewDownloader(syncDir, "", nil, nil, nil, &sync.Map{})
	if got := root.pathToRemote(filepath.Join(syncDir, "top.txt")); got != "top.txt" {
		t.Errorf("root pathToRemote = %q, want top.txt", got)
	}
}

func mustInode(t *testing.T, db *cache.DB, remotePath string) int64 {
	t.Helper()
	id, err := db.UpsertInode(&cache.Inode{RemotePath: remotePath, DisplayName: filepath.Base(remotePath), SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatalf("upsert %q: %v", remotePath, err)
	}
	return id
}
