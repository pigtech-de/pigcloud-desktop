package fsutil

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWithFileLockSerializesReadModifyWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("0"), 0600); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithFileLock(path, func() error {
				raw, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				n := len(raw)
				time.Sleep(time.Millisecond)
				return WriteFileAtomic(path, make([]byte, n+1), 0600)
			})
			if err != nil {
				t.Errorf("lock: %v", err)
			}
		}()
	}
	wg.Wait()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 9 {
		t.Fatalf("file grew to %d bytes, want 9: a read-modify-write was lost", len(raw))
	}
}

func TestWithFileLockReleasesOnPanicFreeReturn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := WithFileLock(path, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + LockSuffix); !os.IsNotExist(err) {
		t.Fatalf("the lock file outlived the holder: %v", err)
	}
	if err := WithFileLock(path, func() error { return nil }); err != nil {
		t.Fatalf("a released lock could not be taken again: %v", err)
	}
}

func TestWithFileLockLeavesAForeignLockInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	lockPath := path + LockSuffix

	err := WithFileLock(path, func() error {
		return os.WriteFile(lockPath, []byte("4242 someone-elses-nonce\n"), 0600)
	})
	if err != nil {
		t.Fatalf("lock: %v", err)
	}

	raw, readErr := os.ReadFile(lockPath)
	if readErr != nil {
		t.Fatalf("the holder deleted a lock it no longer owned: %v", readErr)
	}
	if !strings.Contains(string(raw), "someone-elses-nonce") {
		t.Fatalf("lock file = %q, want the foreign holder's untouched", raw)
	}
}

func TestWithFileLockBreaksAStaleLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	lockPath := path + LockSuffix
	if err := os.WriteFile(lockPath, []byte("999999\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * lockStaleAfter)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}

	ran := false
	if err := WithFileLock(path, func() error { ran = true; return nil }); err != nil {
		t.Fatalf("a crashed holder's lock was never broken: %v", err)
	}
	if !ran {
		t.Error("the guarded body did not run")
	}
}

func TestWithFileLockTimesOutOnALiveHolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path+LockSuffix, []byte("1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(path + LockSuffix) })

	prev := lockWaitTimeoutForTest(50 * time.Millisecond)
	t.Cleanup(func() { lockWaitTimeoutForTest(prev) })

	if err := WithFileLock(path, func() error { return nil }); err == nil {
		t.Fatal("a held lock was entered anyway")
	}
}
