package syncer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func TestReconcilerDoesNotUploadUnchangedBaselineOverNewerRemoteMetadata(t *testing.T) {
	_, db, local := newDownloader(t, "")
	writeFile(t, filepath.Join(local, "notes.txt"), "old")
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Etag: "v1", SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	db.SetLocalContent(id, digestOf("old"), 0)
	db.InvalidateCache(id)
	db.SetInodeSize(id, 5)
	db.SetRemoteVersion(id, "v2")
	reconciler := NewReconciler(local, "", db, time.Minute)
	reconciler.Reconcile(context.Background())
	if queued, _ := db.PendingWritebackCount(); queued != 0 {
		t.Fatalf("unchanged baseline was queued to overwrite a newer remote version: %d", queued)
	}
	inode, err := db.GetInode(id)
	if err != nil || inode.Dirty || inode.SyncStatus == cache.StatusConflict {
		t.Fatalf("ordinary remote update changed clean local content into a conflict: %+v, %v", inode, err)
	}
}
