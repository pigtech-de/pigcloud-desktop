package vfs

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func failureVFS(t *testing.T) (*VFS, *cache.DB, *Node) {
	t.Helper()
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	v := New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "peer.pdf", DisplayName: "peer.pdf", Size: 10})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	node := NewFileNode("peer.pdf", "peer.pdf", 10, time.Now(), nil)
	node.ID = id
	return v, db, node
}

func TestOpenWithheldByRememberedPermanentFailure(t *testing.T) {
	v, db, node := failureVFS(t)
	v.settleDownloadFailure(node, cache.Permanent(errors.New("verify: owner_signing_pk_untrusted")))

	in, _ := db.GetInode(node.ID)
	if in == nil || in.SyncStatus != cache.StatusFailed {
		t.Errorf("permanent failure did not surface on the inode: %+v", in)
	}
	issues, _ := db.ListIssues()
	if len(issues) != 1 {
		t.Errorf("mn files --issues shows %d entries, want 1", len(issues))
	}

	err := v.Open(node)
	if err == nil {
		t.Fatal("a permanently-failed node was opened again with no memory of the failure")
	}
	if !strings.Contains(err.Error(), "owner_signing_pk_untrusted") {
		t.Errorf("open error lost the recorded cause: %v", err)
	}
	if node.OpenCount != 0 {
		t.Errorf("OpenCount = %d after a withheld open, want 0", node.OpenCount)
	}
	if node.Downloading {
		t.Error("node left claimed as downloading")
	}
	select {
	case <-node.DownloadCh:
	default:
		t.Error("waiters never released")
	}
}

func TestDownloadFailureBackoffWindow(t *testing.T) {
	v, db, node := failureVFS(t)

	v.settleDownloadFailure(node, errors.New("connection reset"))
	f, _ := db.GetSyncFailure(node.ID, cache.FailureDownload)
	if f == nil || f.Permanent || f.Attempts != 1 {
		t.Fatalf("transient failure recorded wrong: %+v", f)
	}
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus == cache.StatusFailed {
		t.Errorf("a retryable failure marked the inode failed: %+v", in)
	}
	if f.NextRetryAt <= time.Now().Unix() {
		t.Fatalf("no backoff clock: NextRetryAt=%d now=%d", f.NextRetryAt, time.Now().Unix())
	}
	if err := v.downloadFailureBarrier(node); err == nil {
		t.Error("open allowed inside the backoff window")
	}

	v.settleDownloadFailure(node, errors.New("connection reset again"))
	if f2, _ := db.GetSyncFailure(node.ID, cache.FailureDownload); f2 == nil || f2.Attempts != 2 {
		t.Errorf("attempts did not escalate: %+v", f2)
	}

	f.NextRetryAt = time.Now().Add(-time.Minute).Unix()
	f.Attempts = 2
	db.RecordSyncFailure(f)
	if err := v.downloadFailureBarrier(node); err != nil {
		t.Errorf("open still withheld past the backoff window: %v", err)
	}

	v.settleDownloadFailure(node, nil)
	if f3, _ := db.GetSyncFailure(node.ID, cache.FailureDownload); f3 != nil {
		t.Errorf("a successful download left the failure row: %+v", f3)
	}
	if in, _ := db.GetInode(node.ID); in == nil || in.SyncStatus != cache.StatusSynced {
		t.Errorf("success left the inode looking broken: %+v", in)
	}
}

func TestDownloadFailureIgnoresCancellation(t *testing.T) {
	v, db, node := failureVFS(t)
	v.settleDownloadFailure(node, context.Canceled)
	if f, _ := db.GetSyncFailure(node.ID, cache.FailureDownload); f != nil {
		t.Errorf("cancellation recorded as a failure: %+v", f)
	}
	if err := v.downloadFailureBarrier(node); err != nil {
		t.Errorf("cancellation withheld the next open: %v", err)
	}
}

func TestDownloadFailureBarrierNoRecord(t *testing.T) {
	v, _, node := failureVFS(t)
	if err := v.downloadFailureBarrier(node); err != nil {
		t.Errorf("clean node withheld: %v", err)
	}
	orphan := NewFileNode("x", "x", 1, time.Now(), nil)
	if err := v.downloadFailureBarrier(orphan); err != nil {
		t.Errorf("untracked node withheld: %v", err)
	}
	v.settleDownloadFailure(orphan, cache.Permanent(errors.New("boom")))
	if err := v.downloadFailureBarrier(orphan); err != nil {
		t.Errorf("untracked node withheld after a settle that had nowhere to write: %v", err)
	}
}

func TestWaiterGetsTheDriversFailureNotAPlaceholder(t *testing.T) {
	v, _, node := failureVFS(t)

	node.OpenCount = 1
	node.Downloading = true
	node.DownloadCh = make(chan struct{})

	waited := make(chan error, 1)
	go func() { waited <- v.Open(node) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		node.Mu.RLock()
		blocked := node.OpenCount == 2
		node.Mu.RUnlock()
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second Open never reached the waiter branch")
		}
		time.Sleep(time.Millisecond)
	}

	cause := errors.New("verify: owner_signing_pk_untrusted")
	v.finishDownload(node, cause)

	select {
	case err := <-waited:
		if !errors.Is(err, cause) {
			t.Errorf("waiter got %v, want the driver's %v", err, cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never woke")
	}

	node.Mu.RLock()
	open := node.OpenCount
	node.Mu.RUnlock()
	if open != 0 {
		t.Errorf("OpenCount = %d after a failed waited open, want 0: the node can never be evicted", open)
	}
}

func TestADriverPanicStillReleasesWaiters(t *testing.T) {
	v, _, node := failureVFS(t)

	node.OpenCount = 1
	node.Downloading = true
	node.DownloadCh = make(chan struct{})

	waited := make(chan error, 1)
	go func() { waited <- v.Open(node) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		node.Mu.RLock()
		blocked := node.OpenCount == 2
		node.Mu.RUnlock()
		if blocked {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the second Open never reached the waiter branch")
		}
		time.Sleep(time.Millisecond)
	}

	func() {
		defer func() {
			recover()
		}()
		defer v.finishDownload(node, nil)
		panic("boom")
	}()

	select {
	case <-waited:
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter outlived the driver that panicked")
	}
}
