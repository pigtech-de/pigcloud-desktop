package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGCOrphansReclaimsStrandedTempFiles(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	keep, _ := store.Put([]byte("referenced content"))
	db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Cached: true, ContentHash: keep, SyncStatus: StatusSynced})

	shard := filepath.Dir(store.pathFor(keep))
	stale := time.Now().Add(-2 * time.Hour)
	stranded := []string{
		filepath.Join(shard, ".pigcloud-tmp-123.tmp"),
		filepath.Join(shard, ".tmp-legacy-456"),
	}
	for _, path := range stranded {
		if err := os.WriteFile(path, []byte("half-written blob"), 0600); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
		if err := os.Chtimes(path, stale, stale); err != nil {
			t.Fatalf("age %s: %v", path, err)
		}
	}

	fresh := filepath.Join(shard, ".pigcloud-tmp-inflight.tmp")
	if err := os.WriteFile(fresh, []byte("a write still running"), 0600); err != nil {
		t.Fatalf("seed in-flight temp: %v", err)
	}

	orphanBlob, _ := store.Put([]byte("orphan content nobody references"))

	swept, err := GCOrphans(db, store)
	if err != nil {
		t.Fatalf("GCOrphans: %v", err)
	}
	if swept.Blobs != 1 {
		t.Errorf("swept.Blobs = %d, want 1: a temp file counted as a blob hides a mid-commit crash rate", swept.Blobs)
	}
	if swept.Temps != len(stranded) {
		t.Errorf("swept.Temps = %d, want %d: a blob counted as a temp hides a mid-write crash rate", swept.Temps, len(stranded))
	}
	if store.Has(orphanBlob) {
		t.Error("orphan blob survived GC")
	}

	for _, path := range stranded {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("stranded temp %s survived the sweep: nothing else ever reclaims it", filepath.Base(path))
		}
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Errorf("a temp file younger than the grace window was reclaimed: that races a live Put (%v)", err)
	}
	if !store.Has(keep) {
		t.Error("referenced blob was removed")
	}
}
