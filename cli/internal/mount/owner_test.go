package mount

import (
	"path/filepath"
	"testing"
)

func TestClaimSyncDir(t *testing.T) {
	dir := t.TempDir()

	if err := ClaimSyncDir(dir, "owner-a"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if got := SyncDirOwner(dir); got != "owner-a" {
		t.Fatalf("owner = %q, want owner-a", got)
	}
	if err := ClaimSyncDir(dir, "owner-a"); err != nil {
		t.Fatalf("re-claim same owner: %v", err)
	}
	if err := ClaimSyncDir(dir, "owner-b"); err == nil {
		t.Fatal("cross-account claim succeeded, want error")
	}
	if got := SyncDirOwner(dir); got != "owner-a" {
		t.Fatalf("owner after failed claim = %q, want owner-a", got)
	}
}

func TestClaimSyncDirEmptyOwner(t *testing.T) {
	dir := t.TempDir()
	if err := ClaimSyncDir(dir, ""); err != nil {
		t.Fatalf("empty owner should no-op: %v", err)
	}
	if got := SyncDirOwner(dir); got != "" {
		t.Fatalf("owner = %q, want unset", got)
	}
}

func TestGetSyncDirOwnerKeying(t *testing.T) {
	dirA := t.TempDir()
	dirB := t.TempDir()

	sp := make(SyncPaths)
	sp.SetSyncDir("owner-a", "/Photos", dirA)
	sp.SetSyncDir("owner-b", "/Photos", dirB)

	if got := sp.GetSyncDir("owner-a", "/Photos"); got != dirA {
		t.Fatalf("owner-a dir = %q, want %q", got, dirA)
	}
	if got := sp.GetSyncDir("owner-b", "/Photos"); got != dirB {
		t.Fatalf("owner-b dir = %q, want %q", got, dirB)
	}
}

func TestGetSyncDirLegacyFallback(t *testing.T) {
	legacyDir := t.TempDir()

	sp := SyncPaths{"Photos": legacyDir}

	if got := sp.GetSyncDir("owner-a", "/Photos"); got != legacyDir {
		t.Fatalf("unclaimed legacy dir = %q, want %q", got, legacyDir)
	}

	if err := ClaimSyncDir(legacyDir, "owner-a"); err != nil {
		t.Fatal(err)
	}
	if got := sp.GetSyncDir("owner-a", "/Photos"); got != legacyDir {
		t.Fatalf("own claimed legacy dir = %q, want %q", got, legacyDir)
	}

	if got := sp.GetSyncDir("owner-b", "/Photos"); got == legacyDir {
		t.Fatal("owner-b resolved into owner-a's claimed legacy dir")
	}
}

func TestDefaultSyncDirPerOwner(t *testing.T) {
	base := t.TempDir()
	t.Setenv("APPDATA", filepath.Join(base, "roaming"))
	t.Setenv("LOCALAPPDATA", filepath.Join(base, "local"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "xdg"))

	a := DefaultSyncDir("owner-a", "/Photos")
	b := DefaultSyncDir("owner-b", "/Photos")
	if a == b {
		t.Fatalf("default dirs collide across accounts: %q", a)
	}
}
