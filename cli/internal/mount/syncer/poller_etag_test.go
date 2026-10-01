package syncer

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestPollerAndWarmStartupUseETagInsteadOfEqualSizeAndTimestamp(t *testing.T) {
	p, db, tree, _, setLS := pollFixture(t)
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	node := addExistingFile(t, p, db, "notes.txt", 3, stamp, false, false)
	node.Etag = "v1"
	db.SetRemoteVersion(node.ID, "v1")
	db.SetLocalContent(node.ID, digestOf("old"), stamp.Unix())
	setLS(remoteEntry{name: "notes.txt", size: 3, haveSize: true, modified: stamp, haveMtime: true, etag: "v2"})
	if err := p.pollRecursive(context.Background(), tree.Root); err != nil {
		t.Fatal(err)
	}
	if node.Cached || node.Etag != "v2" {
		t.Fatalf("changed ETag did not invalidate same-size same-time content: cached=%v etag=%q", node.Cached, node.Etag)
	}
	current, baseline, version, err := db.LocalContentState(node.ID)
	if err != nil || current != "" || baseline != digestOf("old") || version != "v1" {
		t.Fatalf("remote invalidation lost the known local baseline: current=%q baseline=%q version=%q err=%v", current, baseline, version, err)
	}
	local := t.TempDir()
	writeFile(t, filepath.Join(local, "notes.txt"), "old")
	d := NewDownloader(local, "", tree, p.client, db, &sync.Map{})
	downloads := 0
	fetch := func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		downloads++
		return []byte("new"), &api.DownloadResult{}, nil
	}
	d.fetchFile = fetch
	d.downloadPending(context.Background())
	bytes, err := os.ReadFile(filepath.Join(local, "notes.txt"))
	if err != nil || string(bytes) != "new" || downloads != 1 {
		t.Fatalf("changed remote ETag did not replace unchanged baseline: %q downloads=%d err=%v", bytes, downloads, err)
	}
	restartedTree := vfs.New("", db, nil, nil, p.client, tree.PublicKey, tree.PrivateKey, tree.NameKey, nil, nil)
	restarted := NewDownloader(local, "", restartedTree, p.client, db, &sync.Map{})
	restarted.fetchFile = fetch
	if err := restarted.InitialSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if downloads != 1 {
		t.Fatalf("warm startup missed the persisted matching ETag and re-downloaded: %d", downloads)
	}
}

func TestVFSRefreshPreservesDirtyVersionConflictBeforePollerRuns(t *testing.T) {
	for _, nodeDirty := range []bool{false, true} {
		p, db, tree, _, setLS := pollFixture(t)
		stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
		node := addExistingFile(t, p, db, "notes.txt", 3, stamp, nodeDirty, true)
		node.Etag = "v1"
		db.SetRemoteVersion(node.ID, "v1")
		db.SetLocalContent(node.ID, digestOf("old"), stamp.Unix())
		setLS(remoteEntry{name: "notes.txt", size: 3, haveSize: true, modified: stamp, haveMtime: true, etag: "v2"})
		tree.Root.Loaded = false
		if _, err := tree.Readdir(tree.Root); err != nil {
			t.Fatal(err)
		}
		if err := p.pollRecursive(context.Background(), tree.Root); err != nil {
			t.Fatal(err)
		}
		inode, err := db.GetInode(node.ID)
		if err != nil || inode.SyncStatus != cache.StatusConflict || node.Etag != "v1" {
			t.Fatalf("VFS refresh erased a dirty remote-version conflict: nodeDirty=%v nodeVersion=%q inode=%+v err=%v", nodeDirty, node.Etag, inode, err)
		}
		current, baseline, version, err := db.LocalContentState(node.ID)
		if err != nil || current != digestOf("old") || baseline != digestOf("old") || version != "v1" {
			t.Fatalf("VFS refresh erased pending-upload content proof: %q %q %q %v", current, baseline, version, err)
		}
		restarted := vfs.New("", db, nil, nil, p.client, tree.PublicKey, tree.PrivateKey, tree.NameKey, nil, nil)
		if _, err := restarted.Readdir(restarted.Root); err != nil {
			t.Fatal(err)
		}
		reloaded := restarted.Root.GetChild("notes.txt")
		if reloaded == nil || reloaded.Etag != "v1" || !reloaded.Dirty || reloaded.SyncStatus != cache.StatusConflict {
			t.Fatalf("cold VFS load erased persisted version conflict: %+v", reloaded)
		}
		writer := NewWritebackProcessor(restarted, p.client, db, nil, "")
		if !writer.heldByConflict(&cache.WritebackEntry{InodeID: node.ID, Action: "upload"}) {
			t.Fatal("writeback no longer holds the conflict restored from VFS")
		}
	}
}
