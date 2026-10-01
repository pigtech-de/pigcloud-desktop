package syncer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestInitialSyncDoesNotAcceptUnindexedEqualSizeCollisionAsSynced(t *testing.T) {
	d, db, local := newDownloader(t, "")
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "LOCAL")
	writeFile(t, filepath.Join(local, "local-only.txt"), "keep uploading new files")
	localInfo, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	remoteTime := localInfo.ModTime()
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 5, Mtime: remoteTime.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	node := vfs.NewFileNode("notes.txt", "notes.txt", 5, remoteTime, nil)
	node.ID = id
	var downloaded, skipped int64
	var tasks sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &tasks); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	d.scanLocalNewFiles()
	reconciler := NewReconciler(local, "", db, time.Minute)
	reconciler.Reconcile(context.Background())
	inode, err := db.GetInode(id)
	if err != nil {
		t.Fatal(err)
	}
	if inode.SyncStatus == cache.StatusSynced && !inode.Dirty {
		t.Fatalf("unindexed local bytes were accepted as remote content using only size: status=%s dirty=%v localHash=%q", inode.SyncStatus, inode.Dirty, inode.LocalHash)
	}
	if inode.SyncStatus != cache.StatusConflict || !inode.Dirty {
		t.Fatalf("unindexed collision must become an explicit conflict: %+v", inode)
	}
	queued, err := db.DequeueWriteback(10, 0)
	if err != nil || len(queued) != 1 || queued[0].RemotePath != "local-only.txt" {
		t.Fatalf("collision safety changed local-only upload discovery: %+v, %v", queued, err)
	}
}

func TestInitialSyncDoesNotDownloadOverUnindexedOlderLocalFile(t *testing.T) {
	d, db, local := newDownloader(t, "")
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "irreplaceable local content")
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(file, old, old); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "download refused by test server", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	cfg := config.Get()
	endpoint := cfg.Endpoint
	t.Cleanup(func() { cfg.Endpoint = endpoint })
	cfg.Endpoint = server.URL
	d.client = api.NewClientWithKey("test")
	remoteTime := time.Now()
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 5, Mtime: remoteTime.Unix()})
	if err != nil {
		t.Fatal(err)
	}
	node := vfs.NewFileNode("notes.txt", "notes.txt", 5, remoteTime, nil)
	node.ID = id
	var downloaded, skipped int64
	var tasks sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &tasks); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	if requests.Load() != 0 {
		t.Fatalf("initial sync requested a replacement download before preserving the unindexed local collision: %d request(s)", requests.Load())
	}
	bytes, err := os.ReadFile(file)
	if err != nil || string(bytes) != "irreplaceable local content" {
		t.Fatalf("initial sync changed existing local bytes: %q, %v", bytes, err)
	}
	inode, err := db.GetInode(id)
	if err != nil || inode.SyncStatus != cache.StatusConflict || !inode.Dirty {
		t.Fatalf("older local collision was not exposed as a conflict: %+v, %v", inode, err)
	}
}
