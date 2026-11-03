package syncer

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/mlog"
	"pigcloud/internal/mount/vfs"
)

func countingServer(t *testing.T) (*api.Client, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true}`)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "test"
	return api.NewClient(), &requests
}

func pollOnce(t *testing.T, p *Poller) {
	t.Helper()
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("pollRecursive: %v", err)
	}
}

func TestLocalSaveKeepsPollerConflict(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	syncDir := t.TempDir()
	store, err := cache.NewStore(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)

	base := time.Now().Add(-time.Hour).Truncate(time.Second).UTC()
	node := addExistingFile(t, p, db, "f.txt", 100, base, false, true)
	setLS(remoteEntry{name: "f.txt", haveSize: true, size: 200})
	pollOnce(t, p)
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("fixture: poll did not mark the conflict: %+v", in)
	}

	local := filepath.Join(syncDir, "f.txt")
	writeFile(t, local, "second local save")
	w := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}
	w.syncFile(local)

	in, _ := db.GetInode(node.ID)
	if in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("a local save cleared the conflict: %+v", in)
	}
	entries, err := db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
	}
	if !NewWritebackProcessor(nil, nil, db, nil, "").heldByConflict(entries[0]) {
		t.Fatal("the save's upload is not held and would overwrite the remote edit")
	}

	pollOnce(t, p)
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("the next poll lost the conflict: %+v", in)
	}
}

func TestRemoteFolderDeleteKeepsUnsyncedLocalFiles(t *testing.T) {
	p, db, v, _, setLS := pollFixture(t)
	syncDir := t.TempDir()
	d := NewDownloader(syncDir, "", v, nil, db, &sync.Map{})
	p.SetLocalDelete(d.RemoveLocal)

	local := func(remote string) string { return filepath.Join(syncDir, filepath.FromSlash(remote)) }
	addDir := func(remote string, attach bool) {
		id, err := db.UpsertInode(&cache.Inode{RemotePath: remote, DisplayName: filepath.Base(remote), IsDir: true, SyncStatus: cache.StatusSynced, NodeID: "node-" + filepath.Base(remote)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(local(remote), 0700); err != nil {
			t.Fatal(err)
		}
		if attach {
			node := vfs.NewDirNode(remote, remote, v.Root)
			node.ID = id
			v.AttachChild(v.Root, node)
		}
	}
	syncedFile := func(remote, content, baseline string) {
		writeFile(t, local(remote), content)
		id, err := db.UpsertInode(&cache.Inode{RemotePath: remote, DisplayName: filepath.Base(remote), Size: int64(len(content)), SyncStatus: cache.StatusSynced, Etag: "v1"})
		if err != nil {
			t.Fatal(err)
		}
		if baseline != "" {
			db.SetLocalContent(id, digestOf(baseline), 0)
		}
	}

	addDir("Docs", true)
	addDir("Docs/sub", false)
	addDir("Gone", true)
	syncedFile("Docs/clean.txt", "clean", "clean")
	syncedFile("Docs/edited.txt", "edited offline", "as synced")
	syncedFile("Docs/sub/clean.txt", "clean", "clean")
	syncedFile("Gone/clean.txt", "clean", "clean")
	syncedFile("Docs/legacy.txt", "no recorded digest", "")
	writeFile(t, local("Docs/dirty.txt"), "pending")
	dirtyID, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs/dirty.txt", DisplayName: "dirty.txt", Size: 7, Dirty: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	db.EnqueueWriteback(dirtyID, "upload", "Docs/dirty.txt", "")
	writeFile(t, local("Docs/new.txt"), "never tracked")

	setLS()
	pollOnce(t, p)

	kept := map[int64]bool{}
	for _, remote := range []string{"Docs/edited.txt", "Docs/dirty.txt", "Docs/new.txt"} {
		if _, err := os.Stat(local(remote)); err != nil {
			t.Errorf("unsynced %s left the sync folder: %v", remote, err)
		}
		in, _ := db.GetInodeByPath(remote)
		if in == nil || !in.Dirty || in.SyncStatus != cache.StatusPending {
			t.Errorf("unsynced %s is not tracked pending: %+v", remote, in)
			continue
		}
		kept[in.ID] = true
	}
	for _, remote := range []string{"Docs/clean.txt", "Docs/legacy.txt", "Docs/sub", "Docs/sub/clean.txt", "Gone", "Gone/clean.txt"} {
		if _, err := os.Lstat(local(remote)); err == nil {
			t.Errorf("synced %s stayed in the sync folder after the remote delete", remote)
		}
		if in, _ := db.GetInodeByPath(remote); in != nil {
			t.Errorf("pruned %s kept its inode", remote)
		}
	}
	docs, _ := db.GetInodeByPath("Docs")
	if docs == nil || docs.SyncStatus != cache.StatusPending || docs.NodeID != "" {
		t.Fatalf("kept folder is not pending re-creation: %+v", docs)
	}

	entries, err := db.DequeueWriteback(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	mkdirs, uploads := 0, 0
	for _, e := range entries {
		switch {
		case e.Action == "mkdir" && e.InodeID == docs.ID:
			mkdirs++
		case e.Action == "upload" && kept[e.InodeID]:
			uploads++
		}
	}
	if mkdirs != 1 || uploads != 3 {
		t.Fatalf("queued %d mkdir and %d uploads, want 1 and 3: %+v", mkdirs, uploads, entries)
	}
}

func TestQueuedDeleteNeverRemovesRecreatedFile(t *testing.T) {
	t.Run("parked delete behind a new upload", func(t *testing.T) {
		db, err := cache.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.EnqueueWriteback(id, "delete", "a.txt", ""); err != nil {
			t.Fatal(err)
		}
		claimed, err := db.DequeueWriteback(10, 0)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("dequeue: %v (%d entries)", err, len(claimed))
		}
		if err := db.DeferWriteback(claimed[0].ID, "503", 1, time.Now().Add(time.Minute).Unix()); err != nil {
			t.Fatal(err)
		}
		if err := db.EnqueueWriteback(id, "upload", "a.txt", ""); err != nil {
			t.Fatal(err)
		}
		rows, err := db.DequeueWriteback(10, time.Now().Add(time.Hour).Unix())
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range rows {
			if e.Action == "delete" {
				t.Fatal("a parked delete outlived the upload of the re-created file and would delete the new content")
			}
		}
	})

	t.Run("delete claimed while the file is back", func(t *testing.T) {
		client, requests := countingServer(t)
		syncDir := t.TempDir()
		db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		v := vfs.New("", db, nil, nil, client, nil, nil, nil, nil, nil)
		w := NewWritebackProcessor(v, client, db, nil, syncDir)

		writeFile(t, filepath.Join(syncDir, "a.txt"), "re-created")
		id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		db.SetLocalContent(id, digestOf("as synced"), 0)
		if err := db.EnqueueWriteback(id, "delete", "a.txt", ""); err != nil {
			t.Fatal(err)
		}
		claimed, err := db.DequeueWriteback(10, 0)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("dequeue: %v (%d entries)", err, len(claimed))
		}
		w.processEntry(context.Background(), claimed[0])

		if n := requests.Load(); n != 0 {
			t.Fatalf("sent %d request(s) to delete a file that exists locally again", n)
		}
		in, _ := db.GetInode(id)
		if in == nil || !in.Dirty || in.SyncStatus != cache.StatusPending {
			t.Errorf("re-created file is not pending upload: %+v", in)
		}
		if active, _ := db.HasActiveWriteback(id, "upload"); !active {
			t.Error("re-created file has no queued upload")
		}
	})
}

func TestRemoteArrivalOverPendingLocalFileConflicts(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 5, Cached: true, Dirty: true, ContentHash: "h-local", SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(id, "upload", "a.txt", ""); err != nil {
		t.Fatal(err)
	}

	setLS(remoteEntry{name: "a.txt", haveSize: true, size: 9, etag: "e-remote"})
	pollOnce(t, p)

	in, _ := db.GetInode(id)
	if in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("remote file arriving over a pending local file is not a conflict: %+v", in)
	}
	if in.ContentHash != "h-local" || !in.Dirty {
		t.Errorf("remote arrival discarded the pending local content: %+v", in)
	}
	entries, err := db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
	}
	if !NewWritebackProcessor(nil, nil, db, nil, "").heldByConflict(entries[0]) {
		t.Fatal("pending upload would replace the other device's file")
	}
}

func TestReconcilerRequeueKeepsUploadBackoff(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	w := NewWritebackProcessor(v, nil, db, nil, syncDir)
	sends := 0
	w.upload = func(context.Context, *cache.WritebackEntry) (uploadedContent, error) {
		sends++
		return uploadedContent{}, errors.New("server unavailable")
	}

	writeFile(t, filepath.Join(syncDir, "a.txt"), "body")
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 4, Dirty: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(id, "upload", "a.txt", ""); err != nil {
		t.Fatal(err)
	}
	drain := func() {
		for {
			rows, err := db.DequeueWriteback(10, time.Now().Add(24*time.Hour).Unix())
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) == 0 {
				return
			}
			for _, e := range rows {
				w.processEntry(context.Background(), e)
			}
		}
	}

	drain()
	if sends != maxRetries {
		t.Fatalf("fixture: first ladder sent %d bodies, want %d", sends, maxRetries)
	}
	f, _ := db.GetSyncFailure(id, cache.FailureUpload)
	if f == nil {
		t.Fatal("fixture: exhausted ladder recorded no failure")
	}
	f.NextRetryAt = 0
	db.RecordSyncFailure(f)

	if healed := NewReconciler(syncDir, "", db, time.Minute).Reconcile(context.Background()); healed != 1 {
		t.Fatalf("fixture: reconciler requeued %d items, want 1", healed)
	}
	drain()

	if extra := sends - maxRetries; extra != 1 {
		t.Errorf("a requeued failing upload sent %d more bodies, want 1", extra)
	}
	if f, _ := db.GetSyncFailure(id, cache.FailureUpload); f == nil || f.Attempts != maxRetries+1 {
		t.Errorf("failure attempts restarted on requeue: %+v", f)
	}
}

func TestQueuedDeleteSurvivesDownloadWalks(t *testing.T) {
	withQueuedDelete := func(t *testing.T) (*Downloader, *vfs.Node, *atomic.Int32) {
		d, db, _ := newDownloader(t, "")
		id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, Etag: "v1", SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		if err := db.EnqueueWriteback(id, "delete", "a.txt", ""); err != nil {
			t.Fatal(err)
		}
		node := vfs.NewFileNode("a.txt", "a.txt", 3, time.Now(), nil)
		node.ID, node.Etag = id, "v1"
		var fetches atomic.Int32
		d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
			fetches.Add(1)
			return []byte("AAA"), &api.DownloadResult{}, nil
		}
		return d, node, &fetches
	}

	t.Run("initial sync walk", func(t *testing.T) {
		d, node, fetches := withQueuedDelete(t)
		var downloaded, skipped int64
		var wg sync.WaitGroup
		d.walkAndSync(context.Background(), node, &downloaded, &skipped, &wg)
		wg.Wait()
		if n := fetches.Load(); n != 0 {
			t.Fatalf("startup walk re-downloaded a file whose local delete is still queued (%d fetches)", n)
		}
	})

	t.Run("runtime walk", func(t *testing.T) {
		d, node, fetches := withQueuedDelete(t)
		var wg sync.WaitGroup
		d.walkForDownloads(context.Background(), node, &wg)
		wg.Wait()
		if n := fetches.Load(); n != 0 {
			t.Fatalf("download loop re-downloaded a file whose local delete is still queued (%d fetches)", n)
		}
	})

	t.Run("identical restore cancels the delete", func(t *testing.T) {
		client, requests := countingServer(t)
		syncDir := t.TempDir()
		db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		w := NewWritebackProcessor(vfs.New("", db, nil, nil, client, nil, nil, nil, nil, nil), client, db, nil, syncDir)
		writeFile(t, filepath.Join(syncDir, "a.txt"), "AAA")
		id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, NodeID: "node-a", SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		db.SetLocalContent(id, digestOf("AAA"), 0)
		if err := db.EnqueueWriteback(id, "delete", "a.txt", ""); err != nil {
			t.Fatal(err)
		}
		claimed, err := db.DequeueWriteback(10, 0)
		if err != nil || len(claimed) != 1 {
			t.Fatalf("dequeue: %v (%d entries)", err, len(claimed))
		}
		w.processEntry(context.Background(), claimed[0])
		if n := requests.Load(); n != 0 {
			t.Fatalf("a restored identical file was deleted remotely (%d requests)", n)
		}
		if in, _ := db.GetInode(id); in == nil || in.NodeID != "node-a" {
			t.Fatalf("the restored file lost its remote node (shares, history): %+v", in)
		}
		if active, _ := db.HasActiveWriteback(id, "upload"); active {
			t.Fatal("an unchanged restored file was queued for a full re-upload")
		}
	})
}

func TestVanishedRemoteEndsConflict(t *testing.T) {
	t.Run("single file", func(t *testing.T) {
		p, db, _, _, setLS := pollFixture(t)
		node := addExistingFile(t, p, db, "f.txt", 10, time.Now(), false, true)
		db.MarkLocalConflict(node.ID, "remote changed while local edits pending")
		db.EnqueueWriteback(node.ID, "upload", "f.txt", "")
		setLS()
		pollOnce(t, p)
		in, _ := db.GetInode(node.ID)
		if in == nil || in.SyncStatus != cache.StatusPending || !in.Dirty {
			t.Fatalf("conflict outlived its remote file; resolve -k remote would discard the only copy: %+v", in)
		}
	})

	t.Run("inside a deleted folder", func(t *testing.T) {
		p, db, v, _, setLS := pollFixture(t)
		syncDir := t.TempDir()
		p.SetLocalDelete(NewDownloader(syncDir, "", v, nil, db, &sync.Map{}).RemoveLocal)
		dirID, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs", DisplayName: "Docs", IsDir: true, SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		dir := vfs.NewDirNode("Docs", "Docs", v.Root)
		dir.ID = dirID
		v.AttachChild(v.Root, dir)
		if err := os.MkdirAll(filepath.Join(syncDir, "Docs"), 0700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(syncDir, "Docs", "c.txt"), "mine")
		id, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs/c.txt", DisplayName: "c.txt", Size: 4, Dirty: true, SyncStatus: cache.StatusConflict})
		if err != nil {
			t.Fatal(err)
		}
		setLS()
		pollOnce(t, p)
		in, _ := db.GetInode(id)
		if in == nil || in.SyncStatus != cache.StatusPending || !in.Dirty {
			t.Fatalf("conflict outlived its deleted folder: %+v", in)
		}
	})
}

func TestFreshSaveRestartsUploadLadder(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, Dirty: true, ContentHash: "old", SyncStatus: cache.StatusFailed})
	if err != nil {
		t.Fatal(err)
	}
	db.RecordSyncFailure(&cache.SyncFailure{InodeID: id, Kind: cache.FailureUpload, Attempts: maxRetries, NextRetryAt: time.Now().Add(time.Hour).Unix()})
	local := filepath.Join(syncDir, "a.txt")
	writeFile(t, local, "new content")
	(&Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}).syncFile(local)
	if f, _ := db.GetSyncFailure(id, cache.FailureUpload); f != nil {
		t.Fatalf("a fresh save inherited the old upload failure ladder: %+v", f)
	}
}

func TestLocalDeleteWhileStoppedIsQueued(t *testing.T) {
	d, db, _ := newDownloader(t, "")
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 3, Etag: "v1", NodeID: "node-a", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(id, digestOf("AAA"), 0, "v1")
	node := vfs.NewFileNode("a.txt", "a.txt", 3, time.Now(), nil)
	node.ID, node.Etag = id, "v1"
	var fetches atomic.Int32
	d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		fetches.Add(1)
		return []byte("AAA"), &api.DownloadResult{}, nil
	}
	var downloaded, skipped int64
	var wg sync.WaitGroup
	d.walkAndSync(context.Background(), node, &downloaded, &skipped, &wg)
	wg.Wait()
	d.flushMissing()
	if n := fetches.Load(); n != 0 {
		t.Fatalf("a file deleted while the daemon was stopped was downloaded again (%d fetches)", n)
	}
	if active, _ := db.HasActiveWriteback(id, "delete"); !active {
		t.Fatal("the local delete was not queued for the remote copy")
	}
}

func TestRemovingAnEditedRemoteFileQueuesItsDelete(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "x.txt", DisplayName: "x.txt", Size: 3, Dirty: true, Etag: "v1", NodeID: "node-x", SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(id, "upload", "x.txt", ""); err != nil {
		t.Fatal(err)
	}
	(&Watcher{syncDir: syncDir, remotePath: "", cacheDB: db}).handleRemove(context.Background(), filepath.Join(syncDir, "x.txt"))
	if in, _ := db.GetInodeByPath("x.txt"); in == nil {
		t.Fatal("an edited file that exists remotely was dropped from tracking; it resurrects on the next start")
	}
	if active, _ := db.HasActiveWriteback(id, "delete"); !active {
		t.Fatal("no remote delete queued for an edited file deleted locally")
	}
	if active, _ := db.HasActiveWriteback(id, "upload"); active {
		t.Fatal("the parked upload survived the delete and would re-create the file")
	}
}

func TestOverflowRescanSeesNestedChangesAndDeletes(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err := os.MkdirAll(filepath.Join(syncDir, "Docs", "sub"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs", DisplayName: "Docs", IsDir: true, NodeID: "node-docs", SyncStatus: cache.StatusSynced}); err != nil {
		t.Fatal(err)
	}
	goneID, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs/gone.txt", DisplayName: "gone.txt", Size: 3, Etag: "v1", NodeID: "node-gone", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(goneID, digestOf("old"), 0, "v1")
	writeFile(t, filepath.Join(syncDir, "Docs", "new.txt"), "new")

	w, err := NewWatcher(syncDir, "", db, store, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	w.rescan(context.Background())

	if active, _ := db.HasActiveWriteback(goneID, "delete"); !active {
		t.Error("a delete missed during the overflow was never queued")
	}
	sub, _ := db.GetInodeByPath("Docs/sub")
	if sub == nil {
		t.Error("a folder created during the overflow was never tracked")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if in, _ := db.GetInodeByPath("Docs/new.txt"); in != nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("a file created in a tracked folder during the overflow was never synced")
}

func TestWatcherKeepsWatchingPastAFailedDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	syncDir := t.TempDir()
	locked, open := filepath.Join(syncDir, "a"), filepath.Join(syncDir, "b")
	for _, dir := range []string{locked, open} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0700) })
	w, err := NewWatcher(syncDir, "", nil, nil, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	w.addRecursive(syncDir)
	if !slices.Contains(w.fsWatcher.WatchList(), open) {
		t.Fatalf("one unwatchable folder stopped the watch of the rest: %v", w.fsWatcher.WatchList())
	}
	if _, ok, category := w.Health(); ok || category != "watch_failed" {
		t.Fatalf("an unwatched folder reported healthy: ok=%v category=%q", ok, category)
	}
}

func TestUnsafeRemoteNameDoesNotBlockPrune(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	node := addExistingFile(t, p, db, "gone.txt", 10, time.Now(), false, false)
	node.ContentHash = ""
	setLS(remoteEntry{name: "a/b", haveSize: true, size: 1})
	pollOnce(t, p)
	if p.vfs.Root.GetChild("gone.txt") != nil {
		t.Fatal("one locally unusable remote name disabled the prune for the whole folder")
	}
}

func TestRecreatedFolderWaitsForItsDeleteThenMkdirs(t *testing.T) {
	client, requests := countingServer(t)
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	dirID, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs", DisplayName: "Docs", IsDir: true, NodeID: "node-docs", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(dirID, "delete", "Docs", ""); err != nil {
		t.Fatal(err)
	}
	if claimed, err := db.DequeueWriteback(10, 0); err != nil || len(claimed) != 1 {
		t.Fatalf("fixture: %d rows (%v)", len(claimed), err)
	}
	if err := os.Mkdir(filepath.Join(syncDir, "Docs"), 0700); err != nil {
		t.Fatal(err)
	}
	w, err := NewWatcher(syncDir, "", db, nil, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	w.handleCreate(context.Background(), filepath.Join(syncDir, "Docs"))
	if active, _ := db.HasActiveWriteback(dirID, "mkdir"); !active {
		t.Fatal("a folder re-created before its delete ran is never re-created remotely")
	}
	wb := NewWritebackProcessor(vfs.New("", db, nil, nil, client, nil, nil, nil, nil, nil), client, db, nil, syncDir)
	rows, err := db.DequeueWriteback(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range rows {
		if e.Action == "mkdir" {
			wb.processEntry(context.Background(), e)
		}
	}
	if n := requests.Load(); n != 0 {
		t.Fatalf("the mkdir ran ahead of the folder's pending delete (%d requests)", n)
	}
}

func TestResolvedLocalIsNotReflaggedByTheSameRemoteVersion(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	node := addExistingFile(t, p, db, "f.txt", 10, time.Now().Add(-time.Hour), false, true)
	node.Etag = "v1"
	db.SetRemoteVersion(node.ID, "v1")
	setLS(remoteEntry{name: "f.txt", haveSize: true, size: 10, etag: "v2"})
	pollOnce(t, p)
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("fixture: no conflict: %+v", in)
	}
	db.MarkDirty(node.ID)
	pollOnce(t, p)
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus == cache.StatusConflict {
		t.Fatalf("a conflict resolved as local was flagged again by the same remote version: %+v", in)
	}
	setLS(remoteEntry{name: "f.txt", haveSize: true, size: 10, etag: "v3"})
	pollOnce(t, p)
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus != cache.StatusConflict {
		t.Fatalf("a newer remote edit after the resolve was not flagged: %+v", in)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestDecryptedNamesNeverReachTheLog(t *testing.T) {
	const secret = "Geheimakte-Steuer-2026"
	logged := &lockedBuffer{}
	level := mlog.CurrentLevel()
	mlog.SetOutput(logged)
	mlog.SetLevel(mlog.LevelDebug)
	t.Cleanup(func() {
		mlog.SetOutput(os.Stderr)
		mlog.SetLevel(level)
	})
	name := secret + ".txt"
	ctx := context.Background()

	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	watcher := &Watcher{syncDir: syncDir, remotePath: "", cacheDB: db, store: store}
	writeFile(t, filepath.Join(syncDir, name), "body")
	watcher.syncFile(filepath.Join(syncDir, name))

	wb := NewWritebackProcessor(vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil), nil, db, store, syncDir)
	calls := 0
	wb.upload = func(context.Context, *cache.WritebackEntry) (uploadedContent, error) {
		calls++
		if calls == 1 {
			return uploadedContent{}, errTeeSealStale
		}
		return uploadedContent{}, fmt.Errorf("upload %s: %w", name, &api.RequestError{Kind: api.KindRateLimited, StatusCode: 429, Err: errors.New("slow down " + name)})
	}
	rows, err := db.DequeueWriteback(10, 0)
	if err != nil || len(rows) != 1 {
		t.Fatalf("fixture: %d rows (%v)", len(rows), err)
	}
	wb.processEntry(ctx, rows[0])

	d := NewDownloader(syncDir, "", vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil), nil, db, &sync.Map{})
	d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		return nil, nil, fmt.Errorf("fetch %s: %w", name, os.ErrNotExist)
	}
	remoteID, err := db.UpsertInode(&cache.Inode{RemotePath: "Remote-" + name, DisplayName: "Remote-" + name, Size: 4, Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	remote := vfs.NewFileNode("Remote-"+name, "Remote-"+name, 4, time.Now(), nil)
	remote.ID, remote.Etag = remoteID, "v1"
	var wg sync.WaitGroup
	d.walkForDownloads(ctx, remote, &wg)
	wg.Wait()

	p, pdb, _, _, setLS := pollFixture(t)
	addExistingFile(t, p, pdb, name, 10, time.Now().Add(-time.Hour), false, true)
	setLS(remoteEntry{name: name, haveSize: true, size: 20, etag: "v2"})
	pollOnce(t, p)

	db.MarkSynced(rows[0].InodeID, "v1")
	os.Remove(filepath.Join(syncDir, name))
	watcher.handleRemove(ctx, filepath.Join(syncDir, name))

	if out := logged.String(); strings.Contains(out, secret) {
		t.Fatalf("a decrypted name reached the daemon log:\n%s", out)
	}
}

func sealedDownload(t *testing.T, plaintext []byte, pub *crypto.PublicKeySet, signPub *crypto.SigningPublicKeySet, signPriv *crypto.SigningPrivateKeySet) ([]byte, string) {
	t.Helper()
	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in, out := filepath.Join(dir, "plain"), filepath.Join(dir, "cipher")
	if err := os.WriteFile(in, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	meta, err := crypto.EncryptFile(in, out, dataKey)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	sealedKey, err := crypto.SealDataKey(dataKey, pub)
	if err != nil {
		t.Fatal(err)
	}
	sigEd, sigMl, err := crypto.SignFileBytes(bytes.NewReader(ciphertext), signPriv)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(api.DownloadPayload{DownloadResult: api.DownloadResult{
		E2EE:             true,
		SealedKey:        base64.StdEncoding.EncodeToString(sealedKey),
		EncryptionMeta:   base64.StdEncoding.EncodeToString(metaJSON),
		SignatureEd25519: base64.StdEncoding.EncodeToString(sigEd),
		SignatureMldsa:   base64.StdEncoding.EncodeToString(sigMl),
		SigningPkEd25519: base64.StdEncoding.EncodeToString(signPub.Ed25519[:]),
		SigningPkMldsa:   base64.StdEncoding.EncodeToString(signPub.Mldsa),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext, base64.StdEncoding.EncodeToString(raw)
}

func TestDownloadStreamsThroughStaging(t *testing.T) {
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte("0123456789abcdef"), 16*1024)
	ciphertext, metaHeader := sealedDownload(t, plaintext, pub, signPub, signPriv)
	half := len(ciphertext) / 2
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseBody := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseBody)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-CLI-Metadata", metaHeader)
		w.Write(ciphertext[:half])
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
		w.Write(ciphertext[half:])
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "test"
	client := api.NewClient()

	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	v := vfs.New("", db, nil, nil, client, pub, priv, nameKey, signPub, signPriv)
	d := NewDownloader(syncDir, "", v, client, db, &sync.Map{})
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "big.bin", DisplayName: "big.bin", Size: int64(len(plaintext)), Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	node := vfs.NewFileNode("big.bin", "big.bin", int64(len(plaintext)), time.Now(), nil)
	node.ID, node.Etag = id, "v1"
	result := make(chan error, 1)
	go func() { result <- d.downloadFile(context.Background(), node) }()

	staged := false
	staging := filepath.Join(syncDir, ".pigcloud", "staging")
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !staged; time.Sleep(20 * time.Millisecond) {
		entries, _ := os.ReadDir(staging)
		for _, e := range entries {
			if info, err := e.Info(); err == nil && info.Size() >= int64(half) {
				staged = true
			}
		}
	}
	releaseBody()
	if err := <-result; err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if !staged {
		t.Fatal("the body never reached the staging folder before it completed; the download is held in memory")
	}
	got, err := os.ReadFile(filepath.Join(syncDir, "big.bin"))
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("published file differs from the plaintext (%d bytes, %v)", len(got), err)
	}
}

func TestDownloadAboveTheOldMemoryCapIsAccepted(t *testing.T) {
	d, db, syncDir := newDownloader(t, "")
	const listed = int64(700) << 20
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "film.mkv", DisplayName: "film.mkv", Size: listed, Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	node := vfs.NewFileNode("film.mkv", "film.mkv", listed, time.Now(), nil)
	node.ID, node.Etag = id, "v1"
	d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		return []byte("frames"), &api.DownloadResult{}, nil
	}
	if err := d.downloadFile(context.Background(), node); err != nil {
		t.Fatalf("a file inside the upload limit was refused: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(syncDir, "film.mkv")); string(got) != "frames" {
		t.Fatalf("published %q", got)
	}
}

func TestReconcilerCheapPassSkipsAnUnchangedStat(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	local := filepath.Join(syncDir, "a.txt")
	writeFile(t, local, "EDIT")
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(local, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 4, Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(id, digestOf("ORIG"), stamp.Unix(), "v1")
	if info, err := os.Stat(local); err == nil {
		db.SetLocalFileID(id, recordedSignature(info, time.Now().Add(time.Minute)))
	}
	r := NewReconciler(syncDir, "", db, time.Minute)
	if healed := r.Reconcile(context.Background()); healed != 0 {
		t.Fatalf("the cheap pass re-read a file whose size and mtime match its record (%d requeued)", healed)
	}
	if healed := r.ReconcileFull(context.Background()); healed != 1 {
		t.Fatalf("the full pass missed a same-stat edit (%d requeued, want 1)", healed)
	}
}

func TestLocalRenameQueuesAMoveNotADeleteAndUpload(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldPath, newPath := filepath.Join(syncDir, "old.txt"), filepath.Join(syncDir, "new.txt")
	writeFile(t, oldPath, "body")
	info, err := os.Stat(oldPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "old.txt", DisplayName: "old.txt", Size: 4, Etag: "v1", NodeID: "node-old", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(id, digestOf("body"), info.ModTime().Unix(), "v1")
	db.SetLocalFileID(id, localFileID(info))
	w, err := NewWatcher(syncDir, "", db, nil, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	w.handleRemove(context.Background(), oldPath)
	w.handleCreate(context.Background(), newPath)

	rows, err := db.DequeueWriteback(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	renames := 0
	for _, e := range rows {
		switch e.Action {
		case "delete":
			t.Fatal("a local rename queued a remote delete")
		case "rename":
			if e.InodeID == id && cache.ParseWritebackExtra(e.ExtraJSON).Target == "new.txt" {
				renames++
			}
		}
	}
	if renames != 1 {
		t.Fatalf("a local rename queued %d moves, want 1: %+v", renames, rows)
	}
	if in, _ := db.GetInodeByPath("new.txt"); in == nil || in.ID != id {
		t.Fatalf("the moved row is not at its new path: %+v", in)
	}
}

func TestRecreatedFolderKeepsItsUnchangedFiles(t *testing.T) {
	setup := func(t *testing.T) (*Watcher, *cache.DB, int64, string) {
		syncDir := t.TempDir()
		db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		store, err := cache.NewStore(filepath.Join(t.TempDir(), "blobs"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(store.Close)
		if err := os.Mkdir(filepath.Join(syncDir, "Docs"), 0700); err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(syncDir, "Docs", "a.txt")
		writeFile(t, child, "body")
		info, _ := os.Stat(child)
		dirID, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs", DisplayName: "Docs", IsDir: true, NodeID: "node-docs", SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		childID, err := db.UpsertInode(&cache.Inode{RemotePath: "Docs/a.txt", DisplayName: "a.txt", Size: 4, Etag: "v1", NodeID: "node-a", SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		db.SetLocalContentForVersion(childID, digestOf("body"), info.ModTime().Unix(), "v1")
		if err := db.EnqueueWriteback(dirID, "delete", "Docs", ""); err != nil {
			t.Fatal(err)
		}
		w, err := NewWatcher(syncDir, "", db, store, nil, nil, &sync.Map{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(w.Stop)
		return w, db, childID, filepath.Join(syncDir, "Docs")
	}
	t.Run("delete still queued", func(t *testing.T) {
		w, db, _, dir := setup(t)
		w.handleCreate(context.Background(), dir)
		if n, _ := db.PendingWritebackCount(); n != 0 {
			rows, _ := db.DequeueWriteback(10, 0)
			for _, e := range rows {
				if e.Action == "delete" {
					t.Fatal("the folder delete still runs and removes the files the re-created folder holds")
				}
			}
		}
	})
	t.Run("delete already running", func(t *testing.T) {
		w, db, childID, dir := setup(t)
		if rows, err := db.DequeueWriteback(10, 0); err != nil || len(rows) != 1 {
			t.Fatalf("fixture: %d rows (%v)", len(rows), err)
		}
		w.handleCreate(context.Background(), dir)
		in, _ := db.GetInode(childID)
		if in == nil || !in.Dirty {
			t.Fatalf("an unchanged file in the re-created folder is not re-uploaded: %+v", in)
		}
		if active, _ := db.HasActiveWriteback(childID, "upload"); !active {
			t.Fatal("no upload queued for a file the running folder delete removes")
		}
	})
}

func TestReusedInodeIsNotAMove(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	newPath := filepath.Join(syncDir, "b.pdf")
	writeFile(t, newPath, "a different document")
	info, err := os.Stat(newPath)
	if err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.pdf", DisplayName: "a.pdf", Size: 3, Etag: "v1", NodeID: "node-a", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(id, digestOf("old"), time.Now().Add(-time.Hour).Unix(), "v1")
	db.SetLocalFileID(id, localFileID(info))
	w, err := NewWatcher(syncDir, "", db, nil, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	w.handleRemove(context.Background(), filepath.Join(syncDir, "a.pdf"))
	w.handleCreate(context.Background(), newPath)
	rows, _ := db.DequeueWriteback(10, 0)
	deleted := false
	for _, e := range rows {
		if e.Action == "rename" {
			t.Fatal("a new file on a reused inode took over the deleted file's node, shares and links")
		}
		deleted = deleted || (e.Action == "delete" && e.InodeID == id)
	}
	if !deleted {
		t.Fatal("the deleted file was never deleted remotely")
	}
}

func TestFailedRenameFallsBackToUpload(t *testing.T) {
	for _, tc := range []struct {
		name         string
		body         string
		wantConflict bool
	}{
		{"name taken", `{"success":false,"errorCode":"path_exists","message":"exists"}`, true},
		{"refused", `{"success":false,"errorCode":"bad_request","message":"no"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tc.body)
			}))
			t.Cleanup(srv.Close)
			config.Get().Endpoint = srv.URL
			config.Get().APIKey = "test"
			client := api.NewClient()
			pub, priv, err := crypto.GenerateHybridKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			nameKey, err := crypto.DeriveNameKey(priv)
			if err != nil {
				t.Fatal(err)
			}
			syncDir := t.TempDir()
			db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			v := vfs.New("", db, nil, nil, client, pub, priv, nameKey, nil, nil)
			wb := NewWritebackProcessor(v, client, db, nil, syncDir)
			writeFile(t, filepath.Join(syncDir, "new.txt"), "body")
			id, err := db.UpsertInode(&cache.Inode{RemotePath: "new.txt", DisplayName: "new.txt", Size: 4, Etag: "v1", NodeID: "0123456789abcdef0123456789abcdef", SyncStatus: cache.StatusSynced})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.EnqueueWriteback(id, "rename", "old.txt", cache.WritebackExtra{Target: "new.txt"}.Marshal()); err != nil {
				t.Fatal(err)
			}
			rows, err := db.DequeueWriteback(10, 0)
			if err != nil || len(rows) != 1 {
				t.Fatalf("fixture: %d rows (%v)", len(rows), err)
			}
			rows[0].Attempts = maxRetries - 1
			wb.processEntry(context.Background(), rows[0])
			in, _ := db.GetInode(id)
			if in == nil || in.SyncStatus == cache.StatusFailed {
				t.Fatalf("a final rename failure left the local and remote names split: %+v", in)
			}
			if tc.wantConflict && in.SyncStatus != cache.StatusConflict {
				t.Errorf("a remote item holding the new name is not a conflict: %+v", in)
			}
			if active, _ := db.HasActiveWriteback(id, "upload"); !active {
				t.Error("the renamed item is never uploaded under its new name")
			}
		})
	}
}

func TestClaimedMoveDropsTheOldPathSync(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	oldPath, newPath := filepath.Join(syncDir, "Old.txt"), filepath.Join(syncDir, "old.txt")
	writeFile(t, oldPath, "body")
	info, _ := os.Stat(oldPath)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "Old.txt", DisplayName: "Old.txt", Size: 4, Etag: "v1", NodeID: "node-old", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(id, digestOf("body"), info.ModTime().Unix(), "v1")
	db.SetLocalFileID(id, localFileID(info))
	w, err := NewWatcher(syncDir, "", db, nil, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
	w.handleRemove(context.Background(), oldPath)
	w.handleCreate(context.Background(), newPath)
	w.mu.Lock()
	_, scheduled := w.pending[oldPath]
	w.mu.Unlock()
	if scheduled {
		t.Fatal("the old name is still scheduled; on a case-insensitive volume it syncs the moved file a second time")
	}
}

func TestPollerDoesNotRestoreAnItemWhoseMoveIsPending(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "new.txt", DisplayName: "new.txt", Size: 4, Etag: "v1", NodeID: "node-moved", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(id, "rename", "old.txt", cache.WritebackExtra{Target: "new.txt"}.Marshal()); err != nil {
		t.Fatal(err)
	}
	setLS(remoteEntry{name: "old.txt", haveSize: true, size: 4, etag: "v1", id: "node-moved"})
	pollOnce(t, p)
	if p.vfs.Root.GetChild("old.txt") != nil {
		t.Fatal("the poller restored the old name of an item whose move is still queued")
	}
	if in, _ := db.GetInodeByPath("old.txt"); in != nil {
		t.Fatalf("the old name got a fresh row and would download again: %+v", in)
	}
}

func TestUnmountedOrMassDeleteIsHeld(t *testing.T) {
	setup := func(t *testing.T) (*Watcher, *cache.DB, string) {
		syncDir := t.TempDir()
		db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err := os.Mkdir(filepath.Join(syncDir, "Media"), 0700); err != nil {
			t.Fatal(err)
		}
		if _, err := db.UpsertInode(&cache.Inode{RemotePath: "Media", DisplayName: "Media", IsDir: true, SyncStatus: cache.StatusSynced}); err != nil {
			t.Fatal(err)
		}
		w, err := NewWatcher(syncDir, "", db, nil, nil, nil, &sync.Map{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(w.Stop)
		return w, db, syncDir
	}
	tracked := func(t *testing.T, db *cache.DB, remote string) int64 {
		id, err := db.UpsertInode(&cache.Inode{RemotePath: remote, DisplayName: filepath.Base(remote), Size: 3, Etag: "v1", SyncStatus: cache.StatusSynced})
		if err != nil {
			t.Fatal(err)
		}
		db.SetLocalContentForVersion(id, digestOf("old"), 1, "v1")
		return id
	}
	t.Run("recorded on another device", func(t *testing.T) {
		w, db, _ := setup(t)
		id := tracked(t, db, "Media/a.mov")
		db.SetLocalFileID(id, "4294967295:7:0")
		w.rescan(context.Background())
		if active, _ := db.HasActiveWriteback(id, "delete"); active {
			t.Fatal("a file recorded on a volume that is not mounted was deleted remotely")
		}
	})
	t.Run("too many at once", func(t *testing.T) {
		w, db, _ := setup(t)
		for i := range 600 {
			tracked(t, db, fmt.Sprintf("Media/f%d.mov", i))
		}
		w.rescan(context.Background())
		if n, _ := db.PendingWritebackCount(); n != 0 {
			t.Fatalf("one detection pass queued %d remote deletes", n)
		}
	})
}

func TestReconcilerScheduleAndSignatureSurviveRestart(t *testing.T) {
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMeta(fullSweepMetaKey, strconv.FormatInt(time.Now().Add(-25*time.Hour).Unix(), 10))
	r := NewReconciler(syncDir, "", db, time.Minute)
	if r.nextFull.After(time.Now()) {
		t.Fatalf("an overdue full pass was postponed to %v by a restart", r.nextFull)
	}
	local := filepath.Join(syncDir, "a.txt")
	writeFile(t, local, "body")
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(local, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.txt", DisplayName: "a.txt", Size: 4, Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContentForVersion(id, digestOf("body"), stamp.Unix(), "v1")
	r.Reconcile(context.Background())
	if in, _ := db.GetInode(id); in == nil || (localFileID(mustStat(t, local)) != "" && in.LocalFileID == "") {
		t.Fatalf("a row without a recorded signature never gets one: %+v", in)
	}
}

func mustStat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestReleaseHeldDeletes(t *testing.T) {
	for _, tc := range []struct {
		choice  string
		deletes int
	}{{"delete", 600}, {"restore", 0}} {
		t.Run(tc.choice, func(t *testing.T) {
			syncDir := t.TempDir()
			db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { db.Close() })
			if err := os.Mkdir(filepath.Join(syncDir, "Media"), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := db.UpsertInode(&cache.Inode{RemotePath: "Media", DisplayName: "Media", IsDir: true, SyncStatus: cache.StatusSynced}); err != nil {
				t.Fatal(err)
			}
			for i := range 600 {
				id, err := db.UpsertInode(&cache.Inode{RemotePath: fmt.Sprintf("Media/f%d.mov", i), DisplayName: fmt.Sprintf("f%d.mov", i), Size: 3, Etag: "v1", SyncStatus: cache.StatusSynced})
				if err != nil {
					t.Fatal(err)
				}
				db.SetLocalContentForVersion(id, digestOf("old"), 1, "v1")
			}
			w, err := NewWatcher(syncDir, "", db, nil, nil, nil, &sync.Map{})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(w.Stop)
			w.rescan(context.Background())
			if n := db.MassDeleteHeld(); n != 600 {
				t.Fatalf("fixture: %d held, want 600", n)
			}
			acted, err := ReleaseHeldDeletes(db, nil, tc.choice)
			if err != nil || acted != 600 {
				t.Fatalf("release acted on %d files (%v), want 600", acted, err)
			}
			if n := db.MassDeleteHeld(); n != 0 {
				t.Fatalf("%d deletes still held after release", n)
			}
			w.rescan(context.Background())
			if n := db.MassDeleteHeld(); n != 0 {
				t.Fatalf("the next detection pass held the released set again (%d)", n)
			}
			if n, _ := db.PendingWritebackCount(); n != tc.deletes {
				t.Fatalf("%d remote deletes queued, want %d", n, tc.deletes)
			}
		})
	}
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := ReleaseHeldDeletes(db, nil, "maybe"); err == nil {
		t.Fatal("an unknown release choice was accepted")
	}
}

func TestWritebackGroupsKeepPathOrder(t *testing.T) {
	row := func(inode int64, action, path string) *cache.WritebackEntry {
		return &cache.WritebackEntry{InodeID: inode, Action: action, RemotePath: path}
	}
	entries := []*cache.WritebackEntry{row(1, "mkdir", "Docs"), row(2, "upload", "Other.txt"), row(3, "upload", "Docs/a.txt"), row(1, "delete", "Docs")}
	groups := groupWriteback(entries)
	if len(groups) != 2 || len(groups[0]) != 3 || groups[0][0] != entries[0] || groups[0][1] != entries[2] || groups[0][2] != entries[3] || groups[1][0] != entries[1] {
		t.Fatalf("groups lost per-path order or merged unrelated rows: %+v", groups)
	}
}

func TestFullSyncQueueHoldsNoGoroutinePerPath(t *testing.T) {
	syncDir := t.TempDir()
	w, err := NewWatcher(syncDir, "", nil, nil, nil, nil, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	w.syncCh = make(chan string)
	before := runtime.NumGoroutine()
	for i := range 200 {
		w.scheduleSync(filepath.Join(syncDir, fmt.Sprintf("f%d.txt", i)))
	}
	time.Sleep(watchDebounce + time.Second)
	if extra := runtime.NumGoroutine() - before; extra > 20 {
		t.Fatalf("%d goroutines parked on a full sync queue, one per pending path", extra)
	}
}
