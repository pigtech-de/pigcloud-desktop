package syncer

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
)

func TestCommittedUploadVersionAllowsTheNextLocalEditWithoutSelfConflict(t *testing.T) {
	p, db, tree, _, setLS := pollFixture(t)
	local := t.TempDir()
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "ONE")
	stamp := time.Now().Add(-time.Hour).Truncate(time.Second)
	node := addExistingFile(t, p, db, "notes.txt", 3, stamp, true, true)
	tree.AttachChild(tree.Root, node)
	node.Etag = strings.Repeat("a", 64)
	db.SetRemoteVersion(node.ID, node.Etag)
	if err := db.EnqueueWriteback(node.ID, "upload", "notes.txt", ""); err != nil {
		t.Fatal(err)
	}
	entries, err := db.DequeueWriteback(1, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("claim upload: %+v, %v", entries, err)
	}
	etag := strings.Repeat("b", 64)
	response := &api.Response{Success: true, Raw: json.RawMessage(`{"success":true,"etag":"` + etag + `"}`)}
	writer := NewWritebackProcessor(tree, p.client, db, nil, local)
	writer.upload = func(context.Context, *cache.WritebackEntry) (uploadedContent, error) {
		return confirmedUploadContent(response, digestOf("ONE")), nil
	}
	if !writer.processEntry(context.Background(), entries[0]) {
		t.Fatal("successful upload failed")
	}
	current, baseline, version, err := db.LocalContentState(node.ID)
	if err != nil || current != digestOf("ONE") || baseline != digestOf("ONE") || version != etag || node.Etag != etag {
		t.Fatalf("confirmed upload did not advance its content proof: %q %q %q nodeVersion=%q err=%v", current, baseline, version, node.Etag, err)
	}
	writeFile(t, file, "TWO")
	db.MarkDirty(node.ID)
	setLS(remoteEntry{name: "notes.txt", size: 3, haveSize: true, modified: stamp.Add(time.Minute), haveMtime: true, etag: etag})
	if err := p.pollRecursive(context.Background(), tree.Root); err != nil {
		t.Fatal(err)
	}
	inode, err := db.GetInode(node.ID)
	if err != nil || inode.SyncStatus == cache.StatusConflict || !inode.Dirty {
		t.Fatalf("next local edit conflicted with its own completed upload: %+v, %v", inode, err)
	}
}

func TestUploadCommitKeepsTheEncryptedSnapshotDigestAndQueuesAnInFlightLocalEdit(t *testing.T) {
	p, db, tree, _, _ := pollFixture(t)
	local := t.TempDir()
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "ONE")
	node := addExistingFile(t, p, db, "notes.txt", 3, time.Now(), true, true)
	tree.AttachChild(tree.Root, node)
	db.EnqueueWriteback(node.ID, "upload", "notes.txt", "")
	entries, err := db.DequeueWriteback(1, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("claim upload: %+v, %v", entries, err)
	}
	etag := strings.Repeat("b", 64)
	writer := NewWritebackProcessor(tree, p.client, db, nil, local)
	writer.upload = func(context.Context, *cache.WritebackEntry) (uploadedContent, error) {
		writeFile(t, file, "TWO")
		return confirmedUploadContent(&api.Response{Success: true, Raw: json.RawMessage(`{"success":true,"etag":"` + etag + `"}`)}, digestOf("ONE")), nil
	}
	if !writer.processEntry(context.Background(), entries[0]) {
		t.Fatal("committed first upload did not complete")
	}
	current, baseline, version, err := db.LocalContentState(node.ID)
	if err != nil || current != digestOf("ONE") || baseline != digestOf("ONE") || version != etag {
		t.Fatalf("uploaded proof was replaced with later local bytes: %q %q %q %v", current, baseline, version, err)
	}
	inode, err := db.GetInode(node.ID)
	if err != nil || !inode.Dirty || !node.Dirty || inode.SyncStatus != cache.StatusPending {
		t.Fatalf("later edit was incorrectly declared synced: %+v nodeDirty=%v err=%v", inode, node.Dirty, err)
	}
	if queued, _ := db.PendingWritebackCount(); queued != 1 {
		t.Fatalf("later local edit was not queued separately: %d", queued)
	}
}
