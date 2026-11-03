package daemon

import (
	"bytes"
	"encoding/json"
	"testing"

	"pigcloud/internal/mount"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestReleaseActionReportsFilesActedOn(t *testing.T) {
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "a.mov", DisplayName: "a.mov", Size: 3, SyncStatus: cache.StatusSynced})
	if err != nil {
		t.Fatal(err)
	}
	sd := &SyncDaemon{cacheDB: db, vfs: vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)}
	call := func(choice string) mount.DaemonResponse {
		var out bytes.Buffer
		if !sd.handleExtra(mount.DaemonRequest{Action: "release", Choice: choice}, json.NewEncoder(&out)) {
			t.Fatal("release is not a sync-daemon action")
		}
		var resp mount.DaemonResponse
		if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp
	}
	db.SetMassDeleteHeld("watcher", []int64{id})
	if resp := call("restore"); !resp.OK || resp.Retried != 1 {
		t.Fatalf("restore reply %+v, want ok with retried 1", resp)
	}
	db.SetMassDeleteHeld("watcher", []int64{id})
	if resp := call("delete"); !resp.OK || resp.Retried != 1 {
		t.Fatalf("delete reply %+v, want ok with retried 1", resp)
	}
	if resp := call("later"); resp.OK {
		t.Fatalf("an unknown choice was accepted: %+v", resp)
	}
	if !isMutatingIPC("release") {
		t.Fatal("release runs outside the shutdown mutation gate")
	}
}
