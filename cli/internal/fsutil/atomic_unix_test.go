//go:build unix

package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteFileAtomicInstallsANewInode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := WriteFileAtomic(path, []byte("first"), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	before := inodeOf(t, path)

	if err := WriteFileAtomic(path, []byte("second"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if after := inodeOf(t, path); after == before {
		t.Fatal("rewrite reused the destination inode: the write was in place, not a temp plus rename")
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		t.Skip("no inode information on this platform")
	}
	return uint64(st.Ino)
}
