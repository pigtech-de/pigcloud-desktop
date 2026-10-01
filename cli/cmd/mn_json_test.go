package cmd

import (
	"encoding/json"
	"testing"

	"pigcloud/internal/mount"
)

func decode(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func hasKeys(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %v", k, m)
		}
	}
}

func TestBuildMountStatusJSON_SyncMode(t *testing.T) {
	info := &mount.MountInfo{Owner: "abcd1234"}
	resp := &mount.DaemonResponse{
		OK:           true,
		Online:       true,
		Mode:         mount.ModeSync,
		MountPoint:   "P:",
		RemotePath:   "/Photos",
		SyncDir:      "/home/u/PigCloud",
		CacheUsed:    1048576,
		CacheMax:     104857600,
		PendingCount: 2,
		FailedCount:  1,
		LastPoll:     "5s ago",
		Uptime:       "1h2m3s",
	}

	m := decode(t, buildMountStatusJSON(info, resp))

	hasKeys(t, m, "running", "mode", "mount_point", "remote_path", "sync_dir",
		"owner", "online", "cache_used", "cache_max", "pending", "failed",
		"last_poll", "uptime")

	if m["running"] != true {
		t.Errorf("running: want true, got %v", m["running"])
	}
	if m["mode"] != "sync" {
		t.Errorf("mode: want sync, got %v", m["mode"])
	}
	if m["sync_dir"] != "/home/u/PigCloud" {
		t.Errorf("sync_dir: want set, got %v", m["sync_dir"])
	}
	if m["owner"] != "abcd1234" {
		t.Errorf("owner: want abcd1234, got %v", m["owner"])
	}
	if _, ok := m["cache_used"].(float64); !ok {
		t.Errorf("cache_used should be a JSON number, got %T", m["cache_used"])
	}
	if v, ok := m["pending"].(float64); !ok || v != 2 {
		t.Errorf("pending: want number 2, got %v (%T)", m["pending"], m["pending"])
	}
	if _, ok := m["last_poll"].(string); !ok {
		t.Errorf("last_poll should stay a string, got %T", m["last_poll"])
	}
	if _, ok := m["uptime"].(string); !ok {
		t.Errorf("uptime should stay a string, got %T", m["uptime"])
	}
}

func TestBuildMountStatusJSON_VirtualModeOmitsSyncDir(t *testing.T) {
	resp := &mount.DaemonResponse{
		OK:         true,
		Mode:       mount.ModeVirtual,
		MountPoint: "/mnt/pigcloud",
		RemotePath: "/",
	}

	m := decode(t, buildMountStatusJSON(nil, resp))

	if _, ok := m["sync_dir"]; ok {
		t.Errorf("virtual mode must omit sync_dir, got %v", m["sync_dir"])
	}
	if _, ok := m["owner"]; ok {
		t.Errorf("nil mount info must omit owner, got %v", m["owner"])
	}
	if m["mode"] != "virtual" {
		t.Errorf("mode: want virtual, got %v", m["mode"])
	}
	hasKeys(t, m, "running", "online", "cache_used", "cache_max", "pending", "failed")
}

func TestBuildMountStatusJSON_LegacyModeFallsBackToVirtual(t *testing.T) {
	resp := &mount.DaemonResponse{OK: true, MountPoint: "/mnt", RemotePath: "/"}
	m := decode(t, buildMountStatusJSON(nil, resp))
	if m["mode"] != "virtual" {
		t.Errorf("empty mode should fall back to virtual, got %v", m["mode"])
	}
}

func TestMountStatusListJSON_NotRunning(t *testing.T) {
	m := decode(t, mountStatusListJSON{Mounts: []mountStatusJSON{}})

	if m["running"] != false {
		t.Errorf("running: want false, got %v", m["running"])
	}
	arr, ok := m["mounts"].([]any)
	if !ok || len(arr) != 0 {
		t.Errorf("mounts must be an empty array, got %v", m["mounts"])
	}
	if len(m) != 2 {
		t.Errorf("not-running must be exactly {running:false, mounts:[]}, got %v", m)
	}
}

func TestStaleMountStatusJSON(t *testing.T) {
	info := &mount.MountInfo{
		Mode:       mount.ModeSync,
		MountPoint: "P:",
		RemotePath: "/Photos",
		SyncDir:    "/home/u/PigCloud",
		Owner:      "abcd1234",
	}
	m := decode(t, staleMountStatusJSON(info))

	if m["running"] != false {
		t.Errorf("running: want false, got %v", m["running"])
	}
	if m["stale"] != true {
		t.Errorf("stale: want true, got %v", m["stale"])
	}
	if m["remote_path"] != "/Photos" {
		t.Errorf("remote_path: want /Photos, got %v", m["remote_path"])
	}
	if m["owner"] != "abcd1234" {
		t.Errorf("owner: want abcd1234, got %v", m["owner"])
	}
}

func TestStaleMountStatusJSON_LegacyModeFallsBackToVirtual(t *testing.T) {
	m := decode(t, staleMountStatusJSON(&mount.MountInfo{RemotePath: "/"}))
	if m["mode"] != "virtual" {
		t.Errorf("empty mode should fall back to virtual, got %v", m["mode"])
	}
	if m["remote_path"] != "/" {
		t.Errorf("root remote should render as /, got %v", m["remote_path"])
	}
}

func TestMountStatusListJSON_MixedLiveAndStale(t *testing.T) {
	live := buildMountStatusJSON(&mount.MountInfo{Owner: "abcd1234"}, &mount.DaemonResponse{
		OK: true, Online: true, Mode: mount.ModeSync, MountPoint: "P:", RemotePath: "/Photos",
	})
	stale := staleMountStatusJSON(&mount.MountInfo{Mode: mount.ModeSync, MountPoint: "Q:", RemotePath: "/Docs"})
	m := decode(t, mountStatusListJSON{Running: true, Mounts: []mountStatusJSON{live, stale}})

	arr, ok := m["mounts"].([]any)
	if !ok || len(arr) != 2 {
		t.Fatalf("mounts must carry both entries, got %v", m["mounts"])
	}
	first := arr[0].(map[string]any)
	second := arr[1].(map[string]any)
	if first["running"] != true || second["running"] != false || second["stale"] != true {
		t.Errorf("live/stale flags wrong: %v / %v", first, second)
	}
}
