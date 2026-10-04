package syncer

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func newUploadFixture(t *testing.T) (*WritebackProcessor, *cache.DB, int64, *cache.WritebackEntry) {
	t.Helper()
	syncDir := t.TempDir()
	db, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	v := vfs.New("", db, nil, nil, nil, nil, nil, nil, nil, nil)
	w := NewWritebackProcessor(v, nil, db, nil, syncDir)

	id, err := db.UpsertInode(&cache.Inode{
		RemotePath: "ghost.txt", DisplayName: "ghost.txt", Size: 5,
		Dirty: true, SyncStatus: cache.StatusPending,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := db.EnqueueWriteback(id, "upload", "ghost.txt", ""); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	entries, err := db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
	}
	return w, db, id, entries[0]
}

func TestTransientUploadFailureBacksOff(t *testing.T) {
	w, db, _, entry := newUploadFixture(t)

	if w.processEntry(context.Background(), entry) {
		t.Fatal("fixture: upload with no content reported success")
	}

	if soon, _ := db.DequeueWriteback(10, time.Now().Unix()); len(soon) != 0 {
		t.Errorf("retry claimable immediately: the 2s ticker re-sends the whole body (%d row(s))", len(soon))
	}

	retry, _ := db.DequeueWriteback(10, time.Now().Add(time.Hour).Unix())
	if len(retry) != 1 {
		t.Fatalf("transient failure left %d rows, want 1 parked retry", len(retry))
	}
	if retry[0].Attempts != 1 {
		t.Errorf("attempts = %d, want 1", retry[0].Attempts)
	}
	minDefer := time.Now().Add(20 * time.Second).Unix()
	if retry[0].EnqueuedAt < minDefer {
		t.Errorf("retry parked only %ds out, want the 30s first rung",
			retry[0].EnqueuedAt-time.Now().Unix())
	}
}

func TestUploadFailureRecordsRetryWindow(t *testing.T) {
	w, db, id, entry := newUploadFixture(t)
	entry.Attempts = maxRetries - 1

	if w.processEntry(context.Background(), entry) {
		t.Fatal("fixture: upload with no content reported success")
	}

	f, _ := db.GetSyncFailure(id, cache.FailureUpload)
	if f == nil {
		t.Fatal("terminal upload failure recorded nothing")
	}
	if f.Permanent {
		t.Fatalf("a missing local file is not a permanent server rejection: %+v", f)
	}
	if f.NextRetryAt <= time.Now().Unix() {
		t.Errorf("upload failure has no retry clock (NextRetryAt=%d, now=%d)", f.NextRetryAt, time.Now().Unix())
	}
}

func TestTransferBackoff(t *testing.T) {
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{0, 30 * time.Second},
		{1, 30 * time.Second},
		{2, 60 * time.Second},
		{3, 120 * time.Second},
		{4, 240 * time.Second},
		{7, 32 * time.Minute},
		{8, time.Hour},
		{40, time.Hour},
	}
	for _, c := range cases {
		if got := transferBackoff(c.attempts); got != c.want {
			t.Errorf("transferBackoff(%d) = %v, want %v", c.attempts, got, c.want)
		}
	}
	prev := time.Duration(0)
	for a := 1; a <= 20; a++ {
		d := transferBackoff(a)
		if d < prev {
			t.Fatalf("backoff decreased at attempt %d: %v < %v", a, d, prev)
		}
		if d > transferRetryCap {
			t.Fatalf("backoff exceeded cap at attempt %d: %v", a, d)
		}
		prev = d
	}
}

func TestUploadRetryDelay(t *testing.T) {
	rateLimited := func(after time.Duration) error {
		return fmt.Errorf("upload: %w", &api.RequestError{
			Kind: api.KindRateLimited, StatusCode: 429, RetryAfter: after,
			Err: errors.New("daily upload limit"),
		})
	}
	cases := []struct {
		name     string
		err      error
		attempts int
		want     time.Duration
	}{
		{"429 with Retry-After", rateLimited(45 * time.Second), 1, 45 * time.Second},
		{"429 no header", rateLimited(0), 1, 15 * time.Second},
		{"429 no header, third try", rateLimited(0), 3, 45 * time.Second},
		{"429 daily-ledger window is bounded, not discarded", rateLimited(9 * time.Hour), 1, api.MaxRateLimitDelay},
		{"429 spent scan budget parks for the whole window", fmt.Errorf("upload: %w", &api.RequestError{
			Kind: api.KindRateLimited, StatusCode: 429, RetryAfter: 50 * time.Minute,
			Err: &api.APIError{Code: "rate_limited", Message: "Hourly upload limit reached."},
		}), 1, 50 * time.Minute},
		{"503 rides the shared ladder", fmt.Errorf("upload: %w", &api.RequestError{Kind: api.KindTransient, StatusCode: 503, Err: errors.New("scanner unavailable")}), 1, 30 * time.Second},
		{"transport error, second try", errors.New("connection reset"), 2, 60 * time.Second},
	}
	for _, c := range cases {
		if got := writebackRetryDelay(c.err, c.attempts); got != c.want {
			t.Errorf("%s: writebackRetryDelay(_, %d) = %v, want %v", c.name, c.attempts, got, c.want)
		}
	}
}

func TestPermanentWrapper(t *testing.T) {
	if isPermanent(errors.New("plain")) {
		t.Error("plain error must not be permanent")
	}
	if isPermanent(nil) {
		t.Error("nil must not be permanent")
	}
	base := errors.New("verify failed")
	p := permanent(base)
	if !isPermanent(p) {
		t.Error("tagged error not detected as permanent")
	}
	wrapped := fmt.Errorf("download x: %w", p)
	if !isPermanent(wrapped) {
		t.Error("permanent classification lost through fmt.Errorf")
	}
	if !errors.Is(wrapped, base) {
		t.Error("Unwrap chain broken by the permanent wrapper")
	}
}

func TestClassifyUploadError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		perm bool
	}{
		{"400 bad name", &api.RequestError{Kind: api.KindPermanent, StatusCode: 400, Err: errors.New("rejected name")}, true},
		{"409 over quota", &api.RequestError{Kind: api.KindPermanent, StatusCode: 409, Err: errors.New("storage limit")}, true},
		{"429 daily limit", &api.RequestError{Kind: api.KindRateLimited, StatusCode: 429, Err: errors.New("daily upload limit")}, false},
		{"503 tee outage", &api.RequestError{Kind: api.KindTransient, StatusCode: 503, Err: errors.New("scanner unavailable")}, false},
		{"500 save failed", &api.RequestError{Kind: api.KindTransient, StatusCode: 500, Err: errors.New("save failed")}, false},
		{"transport", errors.New("request failed: connection reset"), false},
	}
	for _, c := range cases {
		got := classifyUploadError(fmt.Errorf("upload: %w", c.err))
		if got == nil {
			t.Fatalf("%s: classifyUploadError returned nil", c.name)
		}
		if isPermanent(got) != c.perm {
			t.Errorf("%s: permanent = %v, want %v", c.name, isPermanent(got), c.perm)
		}
	}
}
