package mlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenMountLogAppendsBelowCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")

	lf, err := OpenLog(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	lf.WriteString("first\n")
	lf.Close()

	lf, err = OpenLog(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	lf.WriteString("second\n")
	lf.Close()

	data, _ := os.ReadFile(path)
	if got := string(data); got != "first\nsecond\n" {
		t.Fatalf("append lost data: %q", got)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatalf("rotated below cap, .1 should not exist")
	}
}

func TestOpenMountLogRotatesOverCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")

	big := strings.Repeat("x", MaxLogSize+1)
	if err := os.WriteFile(path, []byte(big), 0600); err != nil {
		t.Fatal(err)
	}

	lf, err := OpenLog(path)
	if err != nil {
		t.Fatalf("open over cap: %v", err)
	}
	lf.WriteString("fresh\n")
	lf.Close()

	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("prior log not rotated to .1: %v", err)
	}
	if len(rotated) != len(big) {
		t.Fatalf(".1 size = %d, want %d", len(rotated), len(big))
	}
	if data, _ := os.ReadFile(path); string(data) != "fresh\n" {
		t.Fatalf("post-rotation log = %q, want fresh start", data)
	}
}

func TestOpenMountLogRotationReplacesPriorArchive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")

	if err := os.WriteFile(path+".1", []byte("stale archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Repeat("y", MaxLogSize+1)), 0600); err != nil {
		t.Fatal(err)
	}

	lf, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	lf.Close()

	if data, _ := os.ReadFile(path + ".1"); string(data) == "stale archive" {
		t.Fatalf(".1 was not replaced by the newly rotated log")
	}
}

func TestRotatingLogRotatesWhileTheDaemonRuns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")

	rl, err := NewRotatingLog(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rl.Close()

	chunk := []byte(strings.Repeat("a", 1<<16))
	written := 0
	for written <= MaxLogSize {
		n, werr := rl.Write(chunk)
		if werr != nil {
			t.Fatalf("write: %v", werr)
		}
		written += n
	}
	rl.Write([]byte("after rotation\n"))

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat live log: %v", err)
	}
	if fi.Size() > MaxLogSize {
		t.Errorf("live log grew to %d, past the %d cap", fi.Size(), MaxLogSize)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("prior log was not rotated to .1: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "after rotation") {
		t.Error("writes after rotation must land in the fresh log")
	}
}

func TestRotatingLogCarriesForwardAnExistingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", MaxLogSize-4)), 0600); err != nil {
		t.Fatal(err)
	}

	rl, err := NewRotatingLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer rl.Close()

	rl.Write([]byte("12345678"))
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("append past the cap on a reopened log must still rotate: %v", err)
	}
}

func TestRotationIsAtomicAndLosesNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")

	inherited, err := OpenLog(path)
	if err != nil {
		t.Fatalf("open the handle the child inherits: %v", err)
	}
	defer inherited.Close()

	rl, err := NewRotatingLog(path)
	if err != nil {
		t.Fatalf("open the daemon logger: %v", err)
	}
	defer rl.Close()

	chunk := []byte(strings.Repeat("a", 1<<16))
	for written := 0; written <= MaxLogSize; {
		n, werr := rl.Write(chunk)
		if werr != nil {
			t.Fatalf("write: %v", werr)
		}
		written += n
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("no rotation happened: %v", err)
	}

	if _, err := inherited.WriteString("panic: boom\n"); err != nil {
		t.Fatalf("write through the inherited handle: %v", err)
	}
	rl.Write([]byte("after rotation\n"))

	live, _ := os.ReadFile(path)
	archived, _ := os.ReadFile(path + ".1")
	if !strings.Contains(string(live), "after rotation") {
		t.Error("the daemon logger did not follow the rotation")
	}
	if !strings.Contains(string(archived), "panic: boom") && !strings.Contains(string(live), "panic: boom") {
		t.Error("a panic trace written across a rotation was destroyed")
	}
	if len(archived) == 0 {
		t.Error("rotation left an empty archive")
	}
}
