package syncer

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestDeferredDownloadPreservesLocalChangesBeforePublication(t *testing.T) {
	for _, change := range []string{"same-size edit", "create", "delete", "dirty", "replace"} {
		t.Run(change, func(t *testing.T) {
			d, db, local := newDownloader(t, "")
			file := filepath.Join(local, "notes.txt")
			stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
			if change != "create" {
				writeFile(t, file, "old")
				if err := os.Chtimes(file, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			}
			id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Etag: "v1"})
			if err != nil {
				t.Fatal(err)
			}
			db.SetLocalContent(id, digestOf("old"), stamp.Unix())
			db.InvalidateCache(id)
			node := vfs.NewFileNode("notes.txt", "notes.txt", 3, stamp, nil)
			node.ID, node.Etag = id, "v2"
			started, finish := make(chan struct{}), make(chan struct{})
			d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
				close(started)
				<-finish
				return []byte("new"), &api.DownloadResult{}, nil
			}
			result := make(chan error, 1)
			go func() { result <- d.downloadFile(context.Background(), node) }()
			<-started
			switch change {
			case "same-size edit", "create":
				writeFile(t, file, "OWN")
				if err := os.Chtimes(file, stamp, stamp); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "dirty":
				db.MarkDirty(id)
			case "replace":
				if err := os.Rename(file, file+".old"); err != nil {
					t.Fatal(err)
				}
				writeFile(t, file, "old")
				os.Chtimes(file, stamp, stamp)
			}
			close(finish)
			err = <-result
			if !errors.Is(err, errDownloadLocalChanged) {
				t.Fatalf("local change did not stop publication: %v", err)
			}
			d.recordDownloadFailure(node, err)
			inode, _ := db.GetInode(id)
			if inode.SyncStatus != cache.StatusConflict || !inode.Dirty {
				t.Fatalf("local change not exposed as a conflict: %+v", inode)
			}
			if failed, _ := db.FailedDownloadCount(); failed != 0 {
				t.Fatalf("conflict incorrectly entered transfer retry queue: %d", failed)
			}
			bytes, err := os.ReadFile(file)
			if change == "delete" {
				if !os.IsNotExist(err) {
					t.Fatalf("download resurrected deleted local file: %q, %v", bytes, err)
				}
			} else {
				want := "old"
				if change == "create" || change == "same-size edit" {
					want = "OWN"
				}
				if err != nil || string(bytes) != want {
					t.Fatalf("download changed local bytes: %q, want %q, err=%v", bytes, want, err)
				}
			}
		})
	}
}

func TestChangedRemoteETagDownloadsOverUnchangedBaselineWithSameSizeAndMtime(t *testing.T) {
	d, db, local := newDownloader(t, "")
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "old")
	stamp := time.Now().Truncate(time.Second)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Mtime: stamp.Unix(), Etag: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContent(id, digestOf("old"), 0)
	db.InvalidateCache(id)
	node := vfs.NewFileNode("notes.txt", "notes.txt", 3, stamp, nil)
	node.ID, node.Etag = id, "v2"
	downloads := 0
	d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		downloads++
		return []byte("new"), &api.DownloadResult{}, nil
	}
	var downloaded, skipped int64
	var tasks sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &tasks); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	bytes, err := os.ReadFile(file)
	if err != nil || string(bytes) != "new" || downloads != 1 {
		t.Fatalf("new remote version was missed: %q, downloads=%d, err=%v", bytes, downloads, err)
	}
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &tasks); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	if downloads != 1 || skipped != 1 {
		t.Fatalf("known current remote content re-downloaded on warm start: downloads=%d skipped=%d", downloads, skipped)
	}
}

func TestDownloadRejectsExistingSymlinkAncestor(t *testing.T) {
	d, _, local := newDownloader(t, "")
	outside := t.TempDir()
	link := filepath.Join(local, "linked")
	if err := os.Symlink(outside, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		if output, junctionErr := exec.Command("cmd", "/c", "mklink", "/J", link, outside).CombinedOutput(); junctionErr != nil {
			t.Fatalf("create test directory junction: %s, %v", output, junctionErr)
		}
	}
	if resolved, safe := d.LocalPath("linked/file.txt"); safe {
		t.Fatalf("download target escaped through a preexisting symlink: %s", resolved)
	}
	if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
		t.Fatalf("external directory was changed: %v, %v", entries, err)
	}
}

func TestDeferredDownloadDoesNotStampOldBodyWithANewerRemoteETag(t *testing.T) {
	d, db, local := newDownloader(t, "")
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "old")
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Etag: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContent(id, digestOf("old"), 0)
	db.InvalidateCache(id)
	node := vfs.NewFileNode("notes.txt", "notes.txt", 3, time.Now(), nil)
	node.ID, node.Etag = id, "v2"
	started, finish := make(chan struct{}), make(chan struct{})
	d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		close(started)
		<-finish
		return []byte("two"), &api.DownloadResult{}, nil
	}
	result := make(chan error, 1)
	go func() { result <- d.downloadFile(context.Background(), node) }()
	<-started
	node.Mu.Lock()
	node.Etag = "v3"
	node.Mu.Unlock()
	db.SetRemoteVersion(id, "v3")
	close(finish)
	err = <-result
	if !errors.Is(err, errDownloadRemoteChanged) {
		t.Fatalf("download with stale remote version was published: %v", err)
	}
	bytes, err := os.ReadFile(file)
	if err != nil || string(bytes) != "old" || node.Cached {
		t.Fatalf("old transfer replaced local baseline or claimed current cache: %q cached=%v err=%v", bytes, node.Cached, err)
	}
	current, baseline, version, err := db.LocalContentState(id)
	if err != nil || current != "" || baseline != digestOf("old") || version != "v1" {
		t.Fatalf("stale transfer was labelled with a future version: current=%q baseline=%q version=%q err=%v", current, baseline, version, err)
	}
}

func TestNewerLocalEditStillConflictsWhenTheRemoteVersionAlsoChanged(t *testing.T) {
	d, db, local := newDownloader(t, "")
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "OWN")
	stamp := time.Now().Add(-time.Hour)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Etag: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContent(id, digestOf("old"), 0)
	node := vfs.NewFileNode("notes.txt", "notes.txt", 3, stamp, nil)
	node.ID, node.Etag = id, "v2"
	var downloaded, skipped int64
	var tasks sync.WaitGroup
	if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &tasks); err != nil {
		t.Fatal(err)
	}
	tasks.Wait()
	inode, err := db.GetInode(id)
	if err != nil || inode.SyncStatus != cache.StatusConflict || !inode.Dirty {
		t.Fatalf("newer local timestamp hid a two-sided version conflict: %+v, %v", inode, err)
	}
	if queued, _ := db.PendingWritebackCount(); queued != 0 {
		t.Fatalf("local edit was queued to overwrite changed remote content: %d", queued)
	}
}

func TestSameTimestampEditDuringDownloadWatcherSuppressionIsReconciled(t *testing.T) {
	d, db, local := newDownloader(t, "")
	file := filepath.Join(local, "notes.txt")
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	node := vfs.NewFileNode("notes.txt", "notes.txt", 3, time.Now().Truncate(time.Second), nil)
	node.ID, node.Etag = id, "v1"
	d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
		return []byte("new"), &api.DownloadResult{}, nil
	}
	if err := d.downloadFile(context.Background(), node); err != nil {
		t.Fatal(err)
	}
	if _, suppressed := d.suppress.Load(file); !suppressed {
		t.Fatal("fixture is not inside the post-download watcher suppression window")
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, file, "OWN")
	if err := os.Chtimes(file, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	reconciler := NewReconciler(local, "", db, time.Minute)
	reconciler.Reconcile(context.Background())
	if queued, _ := db.PendingWritebackCount(); queued != 1 {
		t.Fatalf("same-size same-timestamp edit during watcher suppression was lost: %d queued", queued)
	}
}
