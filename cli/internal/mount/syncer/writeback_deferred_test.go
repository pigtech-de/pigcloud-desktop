package syncer

import (
	"testing"
	"time"

	"pigcloud/internal/mount/cache"
)

func deferredFixture(t *testing.T) (*WritebackProcessor, *cache.DB, int64) {
	t.Helper()
	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	id, err := db.UpsertInode(&cache.Inode{
		RemotePath:  "docs/report.pdf",
		DisplayName: "report.pdf",
		Size:        10,
		Mtime:       time.Now().Unix(),
		Dirty:       true,
		SyncStatus:  cache.StatusPending,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnqueueWriteback(id, "upload", "docs/report.pdf", ""); err != nil {
		t.Fatal(err)
	}
	return NewWritebackProcessor(nil, nil, db, nil, ""), db, id
}

func park(t *testing.T, db *cache.DB, seconds int64) {
	t.Helper()
	entries, err := db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
	}
	if err := db.DeferWriteback(entries[0].ID, "429 slow down", 1, time.Now().Add(time.Duration(seconds)*time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
}

func TestFlushAllReportsBackoffParkedRows(t *testing.T) {
	w, db, _ := deferredFixture(t)
	park(t, db, 30)

	res, err := w.FlushAll(5 * time.Second)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if res.Flushed != 0 {
		t.Fatalf("flushed = %d, want 0: the backoff row must stay parked", res.Flushed)
	}
	if res.Deferred != 1 {
		t.Fatalf("deferred = %d, want 1; a flush that reports 0 with no deferred count leaves the user with no reason", res.Deferred)
	}
	if res.NextDue < 28*time.Second || res.NextDue > 29*time.Second {
		t.Fatalf("next due = %v, want 29s (or 28s if the clock ticked): a row is claimable at enqueued_at <= now+1, so the wait is next-now-1 and reporting next-now overstates it by a second", res.NextDue)
	}
	if n, _ := db.PendingWritebackCount(); n != 1 {
		t.Fatalf("the flush consumed the parked row: %d left, want 1", n)
	}
}

func TestFlushAllReportsNoDeferredRowsWhenNothingIsParked(t *testing.T) {
	w, db, _ := deferredFixture(t)

	entries, _ := db.DequeueWriteback(10, 0)
	for _, e := range entries {
		db.DeleteWriteback(e.ID)
	}

	res, err := w.FlushAll(5 * time.Second)
	if err != nil {
		t.Fatalf("flush: %v", err)
	}
	if res.Deferred != 0 || res.NextDue != 0 {
		t.Fatalf("deferred = %d next due = %v on an empty queue, want 0 and 0", res.Deferred, res.NextDue)
	}
}

func TestDeferredWritebackCountIgnoresClaimableRows(t *testing.T) {
	_, db, _ := deferredFixture(t)

	count, next, err := db.DeferredWritebackCount(time.Now().Unix() + 1)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || next != 0 {
		t.Fatalf("count = %d next = %d on a claimable row; counting it would make every flush look blocked", count, next)
	}

	park(t, db, 45)
	count, next, err = db.DeferredWritebackCount(time.Now().Unix() + 1)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || next <= time.Now().Unix() {
		t.Fatalf("count = %d next = %d, want one row due in the future", count, next)
	}
}

func TestARowAtTheClaimBoundIsNotDeferred(t *testing.T) {
	_, db, _ := deferredFixture(t)

	entries, err := db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
	}
	const due = int64(2_000_000_000)
	if err := db.DeferWriteback(entries[0].ID, "429 slow down", 1, due); err != nil {
		t.Fatal(err)
	}

	count, _, err := db.DeferredWritebackCount(due)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("count = %d at horizon %d; DequeueWriteback claims enqueued_at <= claimBefore, so a row sitting exactly on the bound is about to move and is not deferred", count, due)
	}

	count, next, err := db.DeferredWritebackCount(due - 1)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || next != due {
		t.Fatalf("count = %d next = %d one second under the bound, want 1 and %d", count, next, due)
	}
}
