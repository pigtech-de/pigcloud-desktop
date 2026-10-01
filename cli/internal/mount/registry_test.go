package mount

import (
	"os"
	"path/filepath"
	"testing"
)

func setTestConfigDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	return filepath.Join(dir, "pigcloud")
}

func TestWriteListFindMountEntries(t *testing.T) {
	setTestConfigDir(t)

	a := &MountInfo{Port: 1001, Owner: "own1", RemotePath: "/Photos", MountPoint: "P:", Mode: ModeSync}
	b := &MountInfo{Port: 1002, Owner: "own1", RemotePath: "/Docs", MountPoint: "Q:", Mode: ModeSync}
	if err := WriteMountEntry(a); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := WriteMountEntry(b); err != nil {
		t.Fatalf("write b: %v", err)
	}
	if a.Source == "" || b.Source == "" || a.Source == b.Source {
		t.Fatalf("entries must get distinct source paths: %q vs %q", a.Source, b.Source)
	}

	mounts := ListMounts()
	if len(mounts) != 2 {
		t.Fatalf("want 2 mounts, got %d", len(mounts))
	}
	for _, m := range mounts {
		if m.Source == "" {
			t.Errorf("listed entry missing source path: %+v", m)
		}
	}

	got := FindMount("own1", "Photos")
	if got == nil || got.Port != 1001 {
		t.Fatalf("FindMount should normalize the leading slash, got %+v", got)
	}
	if FindMount("own2", "/Photos") != nil {
		t.Error("FindMount must not match a different owner")
	}
	if FindMount("own1", "/Nope") != nil {
		t.Error("FindMount must not match an unknown remote")
	}
}

func TestWriteMountEntryOverwritesSamePair(t *testing.T) {
	setTestConfigDir(t)

	old := &MountInfo{Port: 1001, Owner: "own1", RemotePath: "/Photos", Mode: ModeSync}
	nu := &MountInfo{Port: 2002, Owner: "own1", RemotePath: "Photos", Mode: ModeSync}
	if err := WriteMountEntry(old); err != nil {
		t.Fatal(err)
	}
	if err := WriteMountEntry(nu); err != nil {
		t.Fatal(err)
	}
	mounts := ListMounts()
	if len(mounts) != 1 || mounts[0].Port != 2002 {
		t.Fatalf("same (owner, remote) must overwrite, got %+v", mounts)
	}
}

func TestEvictMountEntry(t *testing.T) {
	setTestConfigDir(t)

	a := &MountInfo{Port: 1001, Owner: "own1", RemotePath: "/Photos", Mode: ModeSync}
	if err := WriteMountEntry(a); err != nil {
		t.Fatal(err)
	}
	EvictMountEntry(a)
	if got := ListMounts(); len(got) != 0 {
		t.Fatalf("evicted entry still listed: %+v", got)
	}
	EvictMountEntry(nil)
	EvictMountEntry(&MountInfo{})
}

func TestListMountsIncludesLegacyFile(t *testing.T) {
	cfg := setTestConfigDir(t)

	legacy := `{"port":3003,"token":"tok","mount_point":"/mnt","remote_path":"/","mode":"virtual"}`
	if err := os.MkdirAll(cfg, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, "mount.json"), []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}
	entry := &MountInfo{Port: 1001, Owner: "own1", RemotePath: "/Photos", Mode: ModeSync}
	if err := WriteMountEntry(entry); err != nil {
		t.Fatal(err)
	}

	mounts := ListMounts()
	if len(mounts) != 2 {
		t.Fatalf("want registry + legacy = 2, got %d", len(mounts))
	}
	last := mounts[len(mounts)-1]
	if last.Port != 3003 || last.Source == "" {
		t.Fatalf("legacy entry must come last with its source set, got %+v", last)
	}

	if got := FindMount("own1", "/"); got == nil || got.Port != 3003 {
		t.Fatalf("legacy fallback match failed, got %+v", got)
	}
}

func TestListMountsSkipsUnreadableEntries(t *testing.T) {
	cfg := setTestConfigDir(t)

	if err := WriteMountEntry(&MountInfo{Port: 1001, Owner: "own1", RemotePath: "/Photos", Mode: ModeSync}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfg, mountsDirName, "garbage.json"), []byte("{nope"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := ListMounts(); len(got) != 1 {
		t.Fatalf("garbage entry must be skipped, got %+v", got)
	}
}
