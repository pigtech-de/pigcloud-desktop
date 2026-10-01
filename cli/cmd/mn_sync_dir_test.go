package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"pigcloud/internal/mount"
)

func TestDirectSyncDirKeepsExistingFilesAndRecordsAccountMapping(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("APPDATA", configDir)
	t.Setenv("LOCALAPPDATA", configDir)
	t.Setenv("XDG_CONFIG_HOME", configDir)
	local := t.TempDir()
	file := filepath.Join(local, "existing.txt")
	if err := os.WriteFile(file, []byte("keep this file"), 0600); err != nil {
		t.Fatal(err)
	}
	paths := make(mount.SyncPaths)
	if err := configureDirectSyncDir(paths, "account", "/Photos", local, local); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep this file" {
		t.Fatalf("existing file changed: %q, %v", data, err)
	}
	if got := mount.LoadSyncPaths().GetSyncDir("account", "/Photos"); got != local {
		t.Fatalf("persisted sync directory = %q, want %q", got, local)
	}
	if got := mount.SyncDirOwner(local); got != "account" {
		t.Fatalf("folder owner = %q", got)
	}
}

func TestDirectSyncDirRejectsRelativeMissingAndDifferentMountPoints(t *testing.T) {
	local := t.TempDir()
	for _, input := range [][2]string{{"relative", "relative"}, {filepath.Join(local, "missing"), filepath.Join(local, "missing")}, {local, t.TempDir()}} {
		if err := validateDirectSyncDir(input[0], input[1]); err == nil {
			t.Fatalf("accepted incompatible direct directory %q -> %q", input[0], input[1])
		}
	}
}

func TestDirectSyncDirRefusesImplicitMigrationAndForeignOwnership(t *testing.T) {
	configDir := t.TempDir()
	t.Setenv("APPDATA", configDir)
	t.Setenv("LOCALAPPDATA", configDir)
	t.Setenv("XDG_CONFIG_HOME", configDir)
	old, next := t.TempDir(), t.TempDir()
	paths := make(mount.SyncPaths)
	paths.SetSyncDir("account", "/Photos", old)
	if err := configureDirectSyncDir(paths, "account", "/Photos", next, next); err == nil {
		t.Fatal("silently replaced the existing sync folder")
	}
	if paths.GetSyncDir("account", "/Photos") != old {
		t.Fatal("failed migration changed the mapping")
	}
	if err := mount.ClaimSyncDir(next, "foreign"); err != nil {
		t.Fatal(err)
	}
	if err := configureDirectSyncDir(make(mount.SyncPaths), "account", "/New", next, next); err == nil {
		t.Fatal("accepted a folder claimed by another account")
	}
}

func TestDirectSyncDirFlagDefaultsToLegacyMapping(t *testing.T) {
	flag := mnStartCmd.Flags().Lookup("sync-dir")
	if flag == nil || flag.DefValue != "" || flag.Value.Type() != "string" {
		t.Fatal("sync-dir must remain an optional string with no default directory")
	}
}
