package daemon

import (
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"pigcloud/internal/mount"
	"pigcloud/internal/mount/cache"
)

func TestActivityRingOrderingNewestFirst(t *testing.T) {
	var r activityRing
	for i := range 3 {
		r.add(mount.ActivityEvent{Path: "f", Bytes: int64(i)})
	}
	got := r.snapshot()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].Bytes != 2 || got[1].Bytes != 1 || got[2].Bytes != 0 {
		t.Fatalf("expected newest-first 2,1,0, got %d,%d,%d", got[0].Bytes, got[1].Bytes, got[2].Bytes)
	}
}

func TestActivityRingWraparound(t *testing.T) {
	var r activityRing
	total := activityRingSize + 25
	for i := range total {
		r.add(mount.ActivityEvent{Bytes: int64(i)})
	}
	got := r.snapshot()
	if len(got) != activityRingSize {
		t.Fatalf("len = %d, want %d", len(got), activityRingSize)
	}
	if got[0].Bytes != int64(total-1) {
		t.Fatalf("newest = %d, want %d", got[0].Bytes, total-1)
	}
	if got[activityRingSize-1].Bytes != int64(total-activityRingSize) {
		t.Fatalf("oldest = %d, want %d", got[activityRingSize-1].Bytes, total-activityRingSize)
	}
}

func TestActivityRingEmpty(t *testing.T) {
	var r activityRing
	if got := r.snapshot(); len(got) != 0 {
		t.Fatalf("empty ring snapshot len = %d, want 0", len(got))
	}
}

func TestActivityRingConcurrentAppend(t *testing.T) {
	var r activityRing
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				r.add(mount.ActivityEvent{Path: "x", Direction: "upload", Bytes: 1})
			}
		})
	}
	wg.Wait()
	got := r.snapshot()
	if len(got) != activityRingSize {
		t.Fatalf("after concurrent fill len = %d, want %d", len(got), activityRingSize)
	}
	for _, ev := range got {
		if ev.Bytes != 1 || ev.Path != "x" {
			t.Fatalf("corrupted event after concurrent append: %+v", ev)
		}
	}
}

func TestBuildFileEntries(t *testing.T) {
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	defer db.Close()

	if _, err := db.UpsertInode(&cache.Inode{
		RemotePath: "Docs/a.txt", DisplayName: "a.txt", Size: 42,
		Dirty: true, SyncStatus: cache.StatusPending,
	}); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	if _, err := db.UpsertInode(&cache.Inode{
		RemotePath: "Docs/b.txt", DisplayName: "b.txt", Size: 7,
		SyncStatus: cache.StatusFailed, StatusReason: "boom",
	}); err != nil {
		t.Fatalf("upsert b: %v", err)
	}

	entries, err := buildFileEntries(db)
	if err != nil {
		t.Fatalf("buildFileEntries: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(entries))
	}

	byPath := map[string]mount.FileEntry{}
	for _, e := range entries {
		byPath[e.Path] = e
	}
	a := byPath["Docs/a.txt"]
	if a.Status != "pending" || !a.Dirty || a.Size != 42 {
		t.Fatalf("a entry wrong: %+v", a)
	}
	b := byPath["Docs/b.txt"]
	if b.Status != "failed" || b.Reason != "boom" {
		t.Fatalf("b entry wrong: %+v", b)
	}
}

func TestBuildConflictEntries(t *testing.T) {
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	defer db.Close()

	db.UpsertInode(&cache.Inode{RemotePath: "ok.txt", DisplayName: "ok.txt", SyncStatus: cache.StatusSynced})
	db.UpsertInode(&cache.Inode{RemotePath: "fail.txt", DisplayName: "fail.txt", SyncStatus: cache.StatusFailed})
	db.UpsertInode(&cache.Inode{RemotePath: "clash.txt", DisplayName: "clash.txt", SyncStatus: cache.StatusConflict})

	entries, err := buildConflictEntries(db)
	if err != nil {
		t.Fatalf("buildConflictEntries: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("conflict entries = %d, want 1", len(entries))
	}
	if entries[0].Path != "clash.txt" || entries[0].Status != "conflict" {
		t.Fatalf("wrong conflict entry: %+v", entries[0])
	}
}

func TestDaemonResponseOmitemptyForOldStyle(t *testing.T) {
	old := mount.DaemonResponse{OK: true, Online: true, MountPoint: "P:", Uptime: "1s"}
	b, err := json.Marshal(old)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "\"files\"") || strings.Contains(s, "\"activity\"") {
		t.Fatalf("old-style response leaked new keys: %s", s)
	}
}

func TestDaemonResponseFilesActivityRoundTrip(t *testing.T) {
	want := mount.DaemonResponse{
		OK: true,
		Files: []mount.FileEntry{
			{Path: "a.txt", Status: "synced", Size: 3},
			{Path: "b.txt", Status: "conflict", Dirty: true, Pinned: true, Reason: "both changed"},
		},
		Activity: []mount.ActivityEvent{
			{Path: "a.txt", Direction: "upload", Bytes: 3, Timestamp: 100},
			{Path: "c.txt", Direction: "delete", Timestamp: 101, Error: "gone"},
		},
	}
	b, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got mount.DaemonResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Files) != 2 || got.Files[1].Reason != "both changed" || !got.Files[1].Pinned {
		t.Fatalf("files round-trip mismatch: %+v", got.Files)
	}
	if len(got.Activity) != 2 || got.Activity[0].Direction != "upload" || got.Activity[1].Error != "gone" {
		t.Fatalf("activity round-trip mismatch: %+v", got.Activity)
	}
}
