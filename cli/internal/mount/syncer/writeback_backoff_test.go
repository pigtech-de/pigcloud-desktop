package syncer

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestNonUploadRetryIsSpaced(t *testing.T) {
	for _, action := range []string{"mkdir", "delete", "rename"} {
		t.Run(action, func(t *testing.T) {
			w, db := backoffFixture(t)

			id, err := db.UpsertInode(&cache.Inode{
				RemotePath:  "docs",
				DisplayName: "docs",
				IsDir:       true,
				SyncStatus:  cache.StatusPending,
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.EnqueueWriteback(id, action, "docs", "docs-renamed"); err != nil {
				t.Fatal(err)
			}

			entries, err := db.DequeueWriteback(10, 0)
			if err != nil || len(entries) != 1 {
				t.Fatalf("dequeue: %v (%d entries)", err, len(entries))
			}
			before := time.Now().Unix()
			if w.processEntry(context.Background(), entries[0]) {
				t.Fatal("a 429 was reported as a successful writeback")
			}

			pending, err := db.DequeueWriteback(10, before+1)
			if err != nil {
				t.Fatal(err)
			}
			if len(pending) != 0 {
				t.Fatalf("%s retry is claimable immediately after a 429; it must wait out the backoff", action)
			}
		})
	}
}

func backoffFixture(t *testing.T) (*WritebackProcessor, *cache.DB) {
	t.Helper()

	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("name key: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"success":false,"message":"rate limited"}`)
	}))
	t.Cleanup(srv.Close)

	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "test"
	client := api.NewClient()

	v := vfs.New("", db, nil, nil, client, pub, priv, nameKey, nil, nil)
	return NewWritebackProcessor(v, client, db, nil, ""), db
}
