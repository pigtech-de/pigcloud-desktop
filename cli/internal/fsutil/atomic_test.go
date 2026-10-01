package fsutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteFileAtomicWritesAndSetsMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	if err := WriteFileAtomic(path, []byte(`{"a":1}`), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Fatalf("content = %q", got)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("mode = %v, want 0600; state files carry tokens and key pins", fi.Mode().Perm())
		}
	}
	assertNoLeftovers(t, dir)
}

func TestWriteFileAtomicReplacesLongerContentWholesale(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pins.json")

	long := strings.Repeat("x", 4096)
	if err := WriteFileAtomic(path, []byte(long), 0600); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := WriteFileAtomic(path, []byte("short"), 0600); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != "short" {
		t.Fatalf("content = %q", got)
	}
	assertNoLeftovers(t, dir)
}

func TestWriteFileAtomicLeavesTargetOnFailure(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "state.json")

	if err := WriteFileAtomic(path, []byte("data"), 0600); err == nil {
		t.Fatal("write into a missing directory reported success")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("stat: %v", err)
	}
	assertNoLeftovers(t, dir)
}

func TestIsTempNameRecognisesWhatTempPatternProduces(t *testing.T) {
	dir := t.TempDir()

	f, err := os.CreateTemp(dir, TempPattern)
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()

	name := filepath.Base(f.Name())
	if !IsTempName(name) {
		t.Errorf("IsTempName(%q) is false for a name TempPattern just produced. Every sweep that "+
			"skips or reclaims temp files reads this, so the two drifting apart either counts an "+
			"in-progress write as a committed blob or deletes one mid-write", name)
	}
	if !IsTempName(".tmp-legacy-123") {
		t.Error("a temp file an older binary stranded no longer reads as one; nothing else reclaims it")
	}
	for _, committed := range []string{"a1b2c3", "mount-abc.log", "tmp-not-ours", ".pigcloud"} {
		if IsTempName(committed) {
			t.Errorf("IsTempName(%q) is true for a committed name; the sweep would delete it", committed)
		}
	}
}

func assertNoLeftovers(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".pigcloud-tmp-") {
			t.Errorf("temp file %s survived the write", e.Name())
		}
	}
}
