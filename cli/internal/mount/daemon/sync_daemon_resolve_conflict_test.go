package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/syncer"
	"pigcloud/internal/mount/vfs"
)

func resolveFixture(t *testing.T) (*SyncDaemon, *cache.DB, int64, string) {
	t.Helper()
	syncDir := t.TempDir()
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	dl := syncer.NewDownloader(syncDir, "", v, nil, db, &sync.Map{})

	id, err := db.UpsertInode(&cache.Inode{
		RemotePath:  "notes.txt",
		DisplayName: "notes.txt",
		Size:        5,
		Mtime:       time.Now().Unix(),
		Dirty:       true,
		SyncStatus:  cache.StatusConflict,
	})
	if err != nil {
		t.Fatalf("upsert inode: %v", err)
	}
	if err := db.EnqueueWriteback(id, "upload", "notes.txt", ""); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	sd := &SyncDaemon{cacheDB: db, vfs: v, downloader: dl}
	return sd, db, id, syncDir
}

func writebackCount(t *testing.T, db *cache.DB) int {
	t.Helper()
	entries, err := db.DequeueWriteback(100, 0)
	if err != nil {
		t.Fatalf("dequeue: %v", err)
	}
	return len(entries)
}

func TestResolveConflictLocal(t *testing.T) {
	sd, db, id, _ := resolveFixture(t)

	if err := sd.resolveConflict("notes.txt", "local"); err != nil {
		t.Fatalf("resolve local: %v", err)
	}

	inode, err := db.GetInodeByPath("notes.txt")
	if err != nil || inode == nil {
		t.Fatalf("get inode: %v", err)
	}
	if inode.SyncStatus != cache.StatusPending {
		t.Errorf("status = %q, want pending", inode.SyncStatus)
	}
	if !inode.Dirty {
		t.Error("inode not marked dirty after keeping local")
	}
	entries, err := db.DequeueWriteback(100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].InodeID != id || entries[0].Action != "upload" {
		t.Fatalf("want one queued upload for the inode, got %+v", entries)
	}
}

func TestResolveConflictRemote(t *testing.T) {
	sd, db, _, syncDir := resolveFixture(t)
	localFile := filepath.Join(syncDir, "notes.txt")
	if err := os.WriteFile(localFile, []byte("local"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := sd.resolveConflict("notes.txt", "remote"); err != nil {
		t.Fatalf("resolve remote: %v", err)
	}

	if _, err := os.Stat(localFile); !os.IsNotExist(err) {
		t.Errorf("local edit not removed (stat err = %v)", err)
	}
	if n := writebackCount(t, db); n != 0 {
		t.Errorf("writeback queue not cleared: %d entries", n)
	}
	inode, _ := db.GetInodeByPath("notes.txt")
	if inode == nil || inode.SyncStatus != cache.StatusSynced || inode.Dirty {
		t.Errorf("inode not reset to synced: %+v", inode)
	}
}

func TestResolveConflictBoth(t *testing.T) {
	sd, db, _, syncDir := resolveFixture(t)
	localFile := filepath.Join(syncDir, "notes.txt")
	if err := os.WriteFile(localFile, []byte("local"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := sd.resolveConflict("notes.txt", "both"); err != nil {
		t.Fatalf("resolve both: %v", err)
	}

	if _, err := os.Stat(localFile); !os.IsNotExist(err) {
		t.Errorf("original name still present (stat err = %v)", err)
	}
	ents, err := os.ReadDir(syncDir)
	if err != nil {
		t.Fatal(err)
	}
	var copies int
	for _, e := range ents {
		if strings.Contains(e.Name(), "(conflict ") {
			copies++
		}
	}
	if copies != 1 {
		t.Errorf("want exactly one (conflict ...) copy, found %d in %v", copies, ents)
	}
	if n := writebackCount(t, db); n != 0 {
		t.Errorf("writeback queue not cleared: %d entries", n)
	}
}

func TestResolveConflictInvalidChoice(t *testing.T) {
	sd, db, _, _ := resolveFixture(t)

	err := sd.resolveConflict("notes.txt", "bogus")
	if err == nil || !strings.Contains(err.Error(), "unknown choice") {
		t.Fatalf("want unknown-choice error, got %v", err)
	}
	inode, _ := db.GetInodeByPath("notes.txt")
	if inode == nil || inode.SyncStatus != cache.StatusConflict {
		t.Errorf("invalid choice mutated inode state: %+v", inode)
	}
	if n := writebackCount(t, db); n != 1 {
		t.Errorf("invalid choice touched the queue: %d entries", n)
	}
}

func TestResolveConflictNotInConflict(t *testing.T) {
	sd, db, id, _ := resolveFixture(t)
	if err := db.SetSyncStatus(id, cache.StatusSynced, ""); err != nil {
		t.Fatal(err)
	}

	err := sd.resolveConflict("notes.txt", "local")
	if err == nil || !strings.Contains(err.Error(), "not in conflict") {
		t.Fatalf("want not-in-conflict error, got %v", err)
	}
}

func TestResolveConflictNoSuchPath(t *testing.T) {
	sd, _, _, _ := resolveFixture(t)
	err := sd.resolveConflict("missing.txt", "local")
	if err == nil || !strings.Contains(err.Error(), "no such path") {
		t.Fatalf("want no-such-path error, got %v", err)
	}
}
