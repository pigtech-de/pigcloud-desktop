package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsLockRetriesDeletePendingAccessDeniedBeforeEntering(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	attempts, calls := 0, 0
	open := func(path string, flags int, mode os.FileMode) (*os.File, error) {
		attempts++
		if attempts == 1 {
			return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
		}
		return os.OpenFile(path, flags, mode)
	}
	err := withFileLock(path, func() error { calls++; return nil }, open, true)
	if err != nil || attempts != 2 || calls != 1 {
		t.Fatalf("delete-pending contention lost a caller: attempts=%d calls=%d err=%v", attempts, calls, err)
	}
	if _, err := os.Stat(path + LockSuffix); !os.IsNotExist(err) {
		t.Fatalf("retry left a lock behind: %v", err)
	}
}

func TestWindowsLockPermissionFailureRemainsBoundedAndNeverEnters(t *testing.T) {
	previous := lockWaitTimeoutForTest(35 * time.Millisecond)
	t.Cleanup(func() { lockWaitTimeoutForTest(previous) })
	path := filepath.Join(t.TempDir(), "state.json")
	attempts, entered := 0, false
	open := func(path string, flags int, mode os.FileMode) (*os.File, error) {
		attempts++
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	}
	started := time.Now()
	err := withFileLock(path, func() error { entered = true; return nil }, open, true)
	if !errors.Is(err, os.ErrPermission) || entered || attempts < 2 || time.Since(started) > time.Second {
		t.Fatalf("permission denial was unbounded or entered: attempts=%d entered=%v elapsed=%s err=%v", attempts, entered, time.Since(started), err)
	}
}

func TestUnixLockPermissionFailureIsNotRetried(t *testing.T) {
	attempts := 0
	err := withFileLock(filepath.Join(t.TempDir(), "state.json"), func() error {
		t.Fatal("entered without a lock")
		return nil
	}, func(string, int, os.FileMode) (*os.File, error) {
		attempts++
		return nil, os.ErrPermission
	}, false)
	if !errors.Is(err, os.ErrPermission) || attempts != 1 {
		t.Fatalf("non-Windows permission error retried: %d %v", attempts, err)
	}
}
