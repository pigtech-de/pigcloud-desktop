package transfer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/mount/cache"
)

func TestOversizedBodyIsRefusedWhileStreaming(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		for range 64 {
			io.WriteString(w, strings.Repeat("x", 1024))
			w.(http.Flusher).Flush()
		}
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "test"
	staging := t.TempDir()
	f := Fetcher{Client: api.NewClient(), Tag: "test", MaxBytes: 4096}
	_, err := f.FetchToFile(context.Background(), "big.bin", staging, 0)
	if !errors.Is(err, api.ErrDownloadTooLarge) || !cache.IsPermanent(err) {
		t.Fatalf("an oversized body was not refused as permanent: %v", err)
	}
	if n := requests.Load(); n != 1 {
		t.Fatalf("an oversized body was requested %d times", n)
	}
	entries, _ := os.ReadDir(staging)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && info.Size() > 0 {
			t.Fatalf("the oversized body stayed on disk: %s (%d bytes)", e.Name(), info.Size())
		}
	}
}
