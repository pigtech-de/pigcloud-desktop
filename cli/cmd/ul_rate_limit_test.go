package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
)

type rateLimitedUlServer struct {
	mu       sync.Mutex
	refusals int
	sources  []string
	keys     []string
	times    []time.Time
}

func (s *rateLimitedUlServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var req api.CLIRequest
	if raw, err := base64.StdEncoding.DecodeString(r.Header.Get(api.HeaderCliMetadata)); err == nil {
		_ = json.Unmarshal(raw, &req)
	}
	_, _ = io.Copy(io.Discard, r.Body)

	s.mu.Lock()
	s.sources = append(s.sources, req.Options["source"])
	s.keys = append(s.keys, req.Options["upload_idempotency_key"])
	s.times = append(s.times, time.Now())
	refuse := s.refusals > 0
	if refuse {
		s.refusals--
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if refuse {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		io.WriteString(w, `{"success":false,"errorCode":"rate_limited","retryAfter":1,"bucket":"tee_scan","message":"Hourly upload limit reached."}`)
		return
	}
	io.WriteString(w, `{"success":true,"name":"f.jpg","storedPath":"/f.jpg","storage":{"usedBytes":1,"limitBytes":2}}`)
}

func TestRateLimitGateHoldsAWaiterPastALaterLongerRefusal(t *testing.T) {
	gate := &rateLimitGate{}
	start := time.Now()
	gate.holdUntil(start.Add(100 * time.Millisecond))
	go func() {
		time.Sleep(50 * time.Millisecond)
		gate.holdUntil(start.Add(300 * time.Millisecond))
	}()
	if err := gate.wait(context.Background()); err != nil {
		t.Fatalf("wait: %v", err)
	}
	if elapsed := time.Since(start); elapsed < 290*time.Millisecond {
		t.Errorf("released after %v; a worker woken by the first deadline must honour the later one", elapsed)
	}
}

func TestRateLimitedUploadResendsIdenticalOptionsAfterRetryAfter(t *testing.T) {
	srv := &rateLimitedUlServer{refusals: 1}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	sealedPath := filepath.Join(t.TempDir(), "pc-upload-sealed")
	if err := os.WriteFile(sealedPath, []byte("ciphertext"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	opts := map[string]string{"_original_name": "photo.jpg", "sealed_key": "sealed", "encryption_meta": "meta"}

	resp, err := uploadHonouringRateLimit(context.Background(), api.NewClient(), &rateLimitGate{}, "photo.jpg", sealedPath, "/", nil, opts)
	if err != nil || resp == nil || !resp.Success {
		t.Fatalf("the resend after the window must succeed: resp=%+v err=%v", resp, err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.sources) != 2 {
		t.Fatalf("got %d attempts, want the refused one plus one resend", len(srv.sources))
	}
	for i, source := range srv.sources {
		if source != "f.jpg" {
			t.Errorf("attempt %d sent source %q, want the wire stub f.jpg; the TEE reads the extension from it", i, source)
		}
	}
	if srv.keys[0] == "" || srv.keys[0] != srv.keys[1] {
		t.Errorf("idempotency keys %q then %q; a resend of the same upload must reuse its key", srv.keys[0], srv.keys[1])
	}
	if gap := srv.times[1].Sub(srv.times[0]); gap < 900*time.Millisecond {
		t.Errorf("resent %v after a Retry-After of 1s", gap)
	}
	if opts["_original_name"] != "photo.jpg" {
		t.Errorf("the caller's options were consumed: %v", opts)
	}
}
