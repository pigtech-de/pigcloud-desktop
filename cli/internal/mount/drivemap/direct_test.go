package drivemap

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectDirectoryIsNeverMappedOrRemoved(t *testing.T) {
	directory := t.TempDir()
	file := filepath.Join(directory, "existing.txt")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	mapper := ForDirectory(directory, directory)
	if _, ok := mapper.(directMapper); !ok {
		t.Fatal("existing sync directory would reach the platform drive mapper")
	}
	if err := mapper.Map(directory, directory); err != nil {
		t.Fatal(err)
	}
	if err := mapper.Unmap(directory); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(file); err != nil || string(data) != "keep" {
		t.Fatalf("unmapping changed local data: %q, %v", data, err)
	}
	if !mapper.IsMapped(directory) {
		t.Fatal("existing directory is not available")
	}
}

func TestDistinctMountPointsKeepPlatformMapper(t *testing.T) {
	directory := t.TempDir()
	mapper := ForDirectory(directory, filepath.Join(directory, "mount"))
	if _, ok := mapper.(directMapper); ok {
		t.Fatal("legacy mount point lost platform mapping")
	}
}

func TestDriveAliasesAreNotTheSameDirectDirectoryPath(t *testing.T) {
	info, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if usesDirectDirectory(`C:\Users\test\Photos`, `P:`, info, info) {
		t.Fatal("legacy drive alias selected a direct mapper and would survive shutdown")
	}
	if usesDirectDirectory("/home/test/photos", "/mnt/photos", info, info) {
		t.Fatal("legacy mount alias selected a direct mapper")
	}
}
