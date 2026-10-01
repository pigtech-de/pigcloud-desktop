//go:build !windows

package syncer

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyncUploadScansSkipExternalFileSymlinks(t *testing.T) {
	d, db, local := newDownloader(t, "")
	outside := filepath.Join(t.TempDir(), "secret.txt")
	writeFile(t, outside, "outside the selected sync folder")
	if err := os.Symlink(outside, filepath.Join(local, "linked.txt")); err != nil {
		t.Fatal(err)
	}
	if queued := d.scanLocalNewFiles(); queued != 0 {
		t.Fatalf("initial scan queued a file symlink: %d", queued)
	}
	if queued := NewReconciler(local, "", db, time.Minute).Reconcile(context.Background()); queued != 0 {
		t.Fatalf("reconciler queued a file symlink: %d", queued)
	}
}
