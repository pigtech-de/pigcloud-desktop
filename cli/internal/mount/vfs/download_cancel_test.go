package vfs

import (
	"net/http"
	"testing"
	"time"
)

func TestDownloadAbortsOnShutdownDuringRateLimitBackoff(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handle("dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"success":false,"message":"rate limited"}`))
	})

	node := &Node{RemotePath: "big.bin", Size: 10}

	done := make(chan error, 1)
	go func() { done <- env.fs.downloadAndCache(node) }()

	time.Sleep(300 * time.Millisecond)
	env.fs.Shutdown()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("download ignored shutdown: still inside the rate-limit backoff")
	}
}
