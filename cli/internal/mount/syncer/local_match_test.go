package syncer

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func digestOf(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) }

func sameSizeFixture(t *testing.T, d *Downloader, db *cache.DB, syncDir, name, was, now string) (*vfs.Node, int64) {
	t.Helper()
	if len(was) != len(now) {
		t.Fatalf("fixture: %q and %q must be the same length", was, now)
	}
	localPath := filepath.Join(syncDir, name)
	writeFile(t, localPath, now)

	remoteMtime := time.Now().Add(-2 * time.Hour)
	id, err := db.UpsertInode(&cache.Inode{
		RemotePath: name, DisplayName: name, Size: int64(len(was)),
		Mtime: remoteMtime.Unix(), LocalHash: digestOf(was), SyncStatus: cache.StatusSynced, Etag: "version-a",
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	db.SetLocalContent(id, digestOf(was), 0)
	node := vfs.NewFileNode(name, name, int64(len(was)), remoteMtime, nil)
	node.ID = id
	node.Etag = "version-a"
	return node, id
}

func TestWalkAndSyncUploadsSameSizeOfflineEdit(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	node, id := sameSizeFixture(t, d, db, syncDir, "notes.txt", "aaaaaaaaaa", "bbbbbbbbbb")

	var downloaded, skipped int64
	var wg sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &wg); err != nil {
		t.Fatalf("walkAndSync: %v", err)
	}
	wg.Wait()

	in, _ := db.GetInode(id)
	if in == nil || in.SyncStatus != cache.StatusPending || !in.Dirty {
		t.Fatalf("same-size offline edit not picked up: %+v", in)
	}
	entries, _ := db.DequeueWriteback(10, 0)
	if len(entries) != 1 || entries[0].Action != "upload" || entries[0].RemotePath != "notes.txt" {
		t.Fatalf("edit not queued for upload: %+v", entries)
	}
}

func TestWalkAndSyncAcceptsUnchangedLocalCopy(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	body := "identical on both sides"
	writeFile(t, filepath.Join(syncDir, "same.txt"), body)

	remoteMtime := time.Now().Add(-time.Hour)
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "same.txt", DisplayName: "same.txt", Size: int64(len(body)),
		Mtime: remoteMtime.Unix(), LocalHash: digestOf(body), SyncStatus: cache.StatusSynced, Etag: "version-a",
	})
	db.SetLocalContent(id, digestOf(body), 0)
	node := vfs.NewFileNode("same.txt", "same.txt", int64(len(body)), remoteMtime, nil)
	node.ID = id
	node.Etag = "version-a"

	var downloaded, skipped int64
	var wg sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &wg); err != nil {
		t.Fatalf("walkAndSync: %v", err)
	}
	wg.Wait()

	if skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (digest matches)", skipped)
	}
	if n, _ := db.PendingWritebackCount(); n != 0 {
		t.Errorf("an unchanged copy queued %d upload(s)", n)
	}
	if !node.Cached {
		t.Error("unchanged copy not marked cached")
	}
}

func TestWalkForDownloadsUploadsSameSizeOfflineEdit(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	node, id := sameSizeFixture(t, d, db, syncDir, "doc.txt", "0123456789", "9876543210")

	var wg sync.WaitGroup
	d.walkForDownloads(context.Background(), node, &wg)
	wg.Wait()

	if node.Cached {
		t.Error("a same-size different-content local file was accepted as the cached copy")
	}
	in, _ := db.GetInode(id)
	if in == nil || in.SyncStatus != cache.StatusPending || !in.Dirty {
		t.Fatalf("same-size offline edit not picked up: %+v", in)
	}
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Errorf("pending uploads = %d, want 1", n)
	}
}

func TestWalkForDownloadsConflictsDropInWithoutDigest(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	body := "the copy the user fetched from the web app"
	writeFile(t, filepath.Join(syncDir, "shared.pdf"), body)
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "shared.pdf", DisplayName: "shared.pdf", Size: int64(len(body)),
		Mtime: time.Now().Add(-time.Hour).Unix(),
	})
	node := vfs.NewFileNode("shared.pdf", "shared.pdf", int64(len(body)), time.Now(), nil)
	node.ID = id
	d.recordDownloadFailure(node, permanent(fmt.Errorf("verify shared.pdf: owner_signing_pk_untrusted")))

	var wg sync.WaitGroup
	d.walkForDownloads(context.Background(), node, &wg)
	wg.Wait()

	if node.Cached || !node.Dirty || node.SyncStatus != cache.StatusConflict {
		t.Error("unverified drop-in copy was not preserved as a conflict")
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureDownload); f != nil {
		t.Errorf("download failure survived the drop-in: %+v", f)
	}
}

func TestReconcilerRequeuesSameSizeOfflineEdit(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := NewReconciler(syncDir, "", db, time.Minute)

	writeFile(t, filepath.Join(syncDir, "edited.txt"), "bbbbbbbbbb")
	editID, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "edited.txt", DisplayName: "edited.txt", Size: 10,
		Mtime: time.Now().Add(-time.Hour).Unix(), Cached: true,
		LocalHash: digestOf("aaaaaaaaaa"), SyncStatus: cache.StatusSynced, Etag: "v1",
	})
	db.SetLocalContent(editID, digestOf("aaaaaaaaaa"), 0)

	untouched := filepath.Join(syncDir, "stable.txt")
	writeFile(t, untouched, "cccccccccc")
	info, _ := os.Stat(untouched)
	db.UpsertInode(&cache.Inode{
		RemotePath: "stable.txt", DisplayName: "stable.txt", Size: 10,
		Mtime: info.ModTime().Unix(), Cached: true,
		LocalHash: digestOf("cccccccccc"), SyncStatus: cache.StatusSynced,
	})

	if healed := r.Reconcile(context.Background()); healed != 1 {
		t.Fatalf("healed = %d, want 1 (the same-size edit only)", healed)
	}
	entries, _ := db.DequeueWriteback(100, 0)
	if len(entries) != 1 || entries[0].RemotePath != "edited.txt" {
		t.Fatalf("wrong requeue set: %+v", entries)
	}
}

func TestReadOnlyMountQueuesNothing(t *testing.T) {
	t.Run("walkForDownloads same-size edit", func(t *testing.T) {
		d, db, syncDir := newDownloaderMode(t, "", true)
		node, id := sameSizeFixture(t, d, db, syncDir, "notes.txt", "aaaaaaaaaa", "bbbbbbbbbb")

		var wg sync.WaitGroup
		d.walkForDownloads(context.Background(), node, &wg)
		wg.Wait()

		if n, _ := db.PendingWritebackCount(); n != 0 {
			t.Errorf("read-only mount queued %d upload(s) nothing can drain", n)
		}
		in, _ := db.GetInode(id)
		if in == nil || !in.Dirty {
			t.Errorf("divergence not tracked, so remounting writable would miss it: %+v", in)
		}
		if node.Cached {
			t.Error("a differing local file was accepted as the cached copy")
		}
	})

	t.Run("walkAndSync offline edit", func(t *testing.T) {
		d, db, syncDir := newDownloaderMode(t, "", true)
		writeFile(t, filepath.Join(syncDir, "edit.txt"), "grew while the daemon was down")
		remoteMtime := time.Now().Add(-time.Hour)
		id, _ := db.UpsertInode(&cache.Inode{
			RemotePath: "edit.txt", DisplayName: "edit.txt", Size: 3, Mtime: remoteMtime.Unix(),
		})
		node := vfs.NewFileNode("edit.txt", "edit.txt", 3, remoteMtime, nil)
		node.ID = id

		var downloaded, skipped int64
		var wg sync.WaitGroup
		if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &wg); err != nil {
			t.Fatalf("walkAndSync: %v", err)
		}
		wg.Wait()

		if n, _ := db.PendingWritebackCount(); n != 0 {
			t.Errorf("read-only initial sync queued %d upload(s)", n)
		}
	})

	t.Run("scanLocalNewFiles untracked files and dirs", func(t *testing.T) {
		d, db, syncDir := newDownloaderMode(t, "", true)
		writeFile(t, filepath.Join(syncDir, "dropped.txt"), "user put this here")
		if err := os.Mkdir(filepath.Join(syncDir, "newdir"), 0700); err != nil {
			t.Fatal(err)
		}

		if queued := d.scanLocalNewFiles(); queued != 0 {
			t.Errorf("scanLocalNewFiles reported %d queued on a read-only mount", queued)
		}
		if n, _ := db.PendingWritebackCount(); n != 0 {
			t.Errorf("read-only startup scan queued %d row(s)", n)
		}
		if in, _ := db.GetInodeByPath("dropped.txt"); in == nil {
			t.Error("local-only file was not tracked at all")
		}
	})

	t.Run("writable mount still queues", func(t *testing.T) {
		d, db, syncDir := newDownloader(t, "")
		writeFile(t, filepath.Join(syncDir, "dropped.txt"), "user put this here")
		if queued := d.scanLocalNewFiles(); queued != 1 {
			t.Fatalf("writable scan queued %d, want 1", queued)
		}
		if n, _ := db.PendingWritebackCount(); n != 1 {
			t.Errorf("writable mount queued %d row(s), want 1", n)
		}
	})
}

func TestWatcherDoesNotClaimAnUnsentEditIsSynced(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	w, err := NewWatcher(syncDir, "", db, store, nil, v, &sync.Map{})
	if err != nil {
		t.Fatalf("new watcher: %v", err)
	}
	t.Cleanup(w.Stop)

	local := filepath.Join(syncDir, "edit.txt")
	writeFile(t, local, "the edit that never uploads")
	w.syncFile(local)

	in, _ := db.GetInodeByPath("edit.txt")
	if in == nil {
		t.Fatal("watcher did not track the save")
	}
	if in.LocalHash != "" {
		t.Fatalf("queued-but-unsent edit already claims to be what the remote holds: %q", in.LocalHash)
	}

	d := NewDownloader(syncDir, "", v, nil, db, &sync.Map{})
	info, _ := os.Stat(local)
	if d.localCopyMatches(in.ID, local, info, info.Size(), "") && in.LocalHash != "" {
		t.Error("the stranded edit was accepted as matching the remote")
	}
}

func TestWritebackStartRefusesOnReadOnlyMount(t *testing.T) {
	attemptsAfterATick := func(t *testing.T, readOnly bool) int {
		t.Helper()
		syncDir := t.TempDir()
		db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
		if err != nil {
			t.Fatalf("open db: %v", err)
		}
		t.Cleanup(func() { db.Close() })
		v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
		w := NewWritebackProcessor(v, nil, db, nil, syncDir)

		id, _ := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Dirty: true})
		if err := db.EnqueueWriteback(id, "upload", "a.txt", ""); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
		v.SetReadOnly(readOnly)

		w.Start()
		time.Sleep(debounceDelay + time.Second)
		w.Stop()

		ents, err := db.DequeueWriteback(10, time.Now().Add(time.Hour).Unix())
		if err != nil || len(ents) != 1 {
			t.Fatalf("row vanished: %d entries, err %v", len(ents), err)
		}
		return ents[0].Attempts
	}

	if n := attemptsAfterATick(t, false); n == 0 {
		t.Fatal("control: a writable processor never touched the row, so the window proves nothing")
	}
	if n := attemptsAfterATick(t, true); n != 0 {
		t.Errorf("a read-only mount started the writeback processor and worked the queue (attempts=%d)", n)
	}
}

func TestRecordUploadedPinsDigestToTheLocalFile(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	w := NewWritebackProcessor(v, nil, db, nil, syncDir)

	body := "uploaded bytes"
	local := filepath.Join(syncDir, "done.txt")
	writeFile(t, local, body)
	info, _ := os.Stat(local)
	id, _ := db.UpsertInode(&cache.Inode{RemotePath: "done.txt", DisplayName: "done.txt", Size: int64(len(body))})
	entry := &cache.WritebackEntry{InodeID: id, Action: "upload", RemotePath: "done.txt"}

	w.recordUploaded(entry, digestOf(body))
	in, _ := db.GetInode(id)
	if in == nil || in.LocalHash != digestOf(body) {
		t.Fatalf("digest not recorded on upload success: %+v", in)
	}
	if in.LocalMtime != info.ModTime().Unix() {
		t.Errorf("timestamp not paired with the digest: %+v", in)
	}

	db.SetLocalContent(id, "", 0)
	w.recordUploaded(entry, "")
	if in, _ := db.GetInode(id); in == nil || in.LocalHash != "" || in.LocalMtime != 0 {
		t.Errorf("empty digest wrote something: %+v", in)
	}
}

func TestReconcilerRefreshesMtimeOnTouchedIdenticalFile(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	r := NewReconciler(syncDir, "", db, time.Minute)

	body := "touched but identical"
	path := filepath.Join(syncDir, "touched.txt")
	writeFile(t, path, body)
	info, _ := os.Stat(path)
	remoteMtime := info.ModTime().Add(-time.Hour).Unix()
	id, _ := db.UpsertInode(&cache.Inode{
		RemotePath: "touched.txt", DisplayName: "touched.txt", Size: int64(len(body)),
		Mtime: remoteMtime, Cached: true,
		LocalHash: digestOf(body), SyncStatus: cache.StatusSynced,
	})

	if healed := r.Reconcile(context.Background()); healed != 0 {
		t.Fatalf("healed = %d, want 0 (content is identical)", healed)
	}
	in, _ := db.GetInode(id)
	if in == nil || in.LocalMtime != info.ModTime().Unix() {
		t.Errorf("local timestamp not refreshed, so every sweep re-hashes: %+v", in)
	}
	if in != nil && in.Mtime != remoteMtime {
		t.Errorf("reconcile overwrote the remote timestamp: %+v", in)
	}
}
