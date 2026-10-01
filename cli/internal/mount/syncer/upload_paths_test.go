package syncer

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func createSyncDirectoryLink(t *testing.T, link, target string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS != "windows" {
			t.Fatal(err)
		}
		if output, junctionErr := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); junctionErr != nil {
			t.Fatalf("create test junction: %s, %v", output, junctionErr)
		}
	}
}

func TestSyncUploadProducersDoNotReadThroughDirectoryLinks(t *testing.T) {
	d, db, local := newDownloader(t, "")
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "secret.txt"), "outside the selected sync folder")
	createSyncDirectoryLink(t, filepath.Join(local, "linked"), outside)
	if queued := d.scanLocalNewFiles(); queued != 0 {
		t.Fatalf("initial scan queued content outside the selected root: %d", queued)
	}
	reconciler := NewReconciler(local, "", db, time.Minute)
	if queued := reconciler.Reconcile(context.Background()); queued != 0 {
		t.Fatalf("reconciler queued linked content outside the selected root: %d", queued)
	}
	store, err := cache.NewStore(filepath.Join(local, ".pigcloud", "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	watcher, err := NewWatcher(local, "", db, store, nil, d.vfs, &sync.Map{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watcher.Stop)
	watcher.syncFile(filepath.Join(local, "linked", "secret.txt"))
	if queued, _ := db.PendingWritebackCount(); queued != 0 {
		t.Fatalf("watcher opened and queued a linked external file: %d", queued)
	}
	writer := NewWritebackProcessor(d.vfs, nil, db, store, local)
	if path, safe := writer.localPath("linked/secret.txt"); safe {
		t.Fatalf("writeback allowed an ancestor link before opening upload content: %s", path)
	}
}
