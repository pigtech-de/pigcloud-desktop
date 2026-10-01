package fsutil

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const LockSuffix = ".lock"

const (
	lockPollInterval = 15 * time.Millisecond
	lockStaleAfter   = 60 * time.Second
)

var lockWaitTimeout = 5 * time.Second

func lockWaitTimeoutForTest(d time.Duration) time.Duration {
	prev := lockWaitTimeout
	lockWaitTimeout = d
	return prev
}

func WithFileLock(path string, fn func() error) error {
	return withFileLock(path, fn, os.OpenFile, runtime.GOOS == "windows")
}

func withFileLock(path string, fn func() error, openFile func(string, int, os.FileMode) (*os.File, error), windows bool) error {
	lockPath := path + LockSuffix
	if err := os.MkdirAll(filepath.Dir(lockPath), 0700); err != nil {
		return err
	}
	deadline := time.Now().Add(lockWaitTimeout)
	for {
		f, err := openFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			nonce := lockNonce()
			fmt.Fprintf(f, "%d %s\n", os.Getpid(), nonce)
			f.Close()
			defer releaseOwnLock(lockPath, nonce)
			return fn()
		}
		exists := errors.Is(err, os.ErrExist)
		deletePending := windows && errors.Is(err, os.ErrPermission)
		if !exists && !deletePending {
			return err
		}
		if time.Now().After(deadline) {
			if deletePending {
				return fmt.Errorf("could not acquire lock before the deadline: %w", err)
			}
			return fmt.Errorf("another pigcloud process is still holding %s", lockPath)
		}
		if exists && breakStaleLock(lockPath) {
			continue
		}
		time.Sleep(lockPollInterval)
	}
}

func lockNonce() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return hex.EncodeToString(raw)
}

func releaseOwnLock(lockPath, nonce string) {
	raw, err := os.ReadFile(lockPath)
	if err != nil || !strings.Contains(string(raw), nonce) {
		return
	}
	os.Remove(lockPath)
}

func breakStaleLock(lockPath string) bool {
	info, err := os.Stat(lockPath)
	if err != nil {
		return errors.Is(err, os.ErrNotExist)
	}
	if time.Since(info.ModTime()) < lockStaleAfter {
		return false
	}
	return os.Remove(lockPath) == nil
}
