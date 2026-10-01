package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUploadIdempotencyKeyUnique(t *testing.T) {
	const n = 2000
	seen := make(map[string]struct{}, n)
	for range n {
		k := NewUploadIdempotencyKey()
		if !uuidV4Re.MatchString(k) {
			t.Fatalf("key %q is not a v4 UUID", k)
		}
		if _, dup := seen[k]; dup {
			t.Fatalf("duplicate key across distinct uploads: %q", k)
		}
		seen[k] = struct{}{}
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(p, []byte(content), 0600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

func TestUploadMintsDistinctKeyPerCall(t *testing.T) {
	client, _, keys := uploadTestServer(t)
	localPath := writeTempFile(t, "payload")

	for i := range 2 {
		if _, err := client.Upload(context.Background(), localPath, "/dst", nil); err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	if len(*keys) != 2 {
		t.Fatalf("got %d requests, want 2", len(*keys))
	}
	if (*keys)[0] == "" || (*keys)[1] == "" {
		t.Fatalf("a request carried no idempotency key: %v", *keys)
	}
	if (*keys)[0] == (*keys)[1] {
		t.Fatalf("two distinct uploads reused one key: %q", (*keys)[0])
	}
}

func TestUploadPreservesSeededKey(t *testing.T) {
	client, _, keys := uploadTestServer(t)
	localPath := writeTempFile(t, "payload")

	seeded := "seeded-key-1234"
	opts := map[string]string{"upload_idempotency_key": seeded}
	if _, err := client.Upload(context.Background(), localPath, "/dst", nil, opts); err != nil {
		t.Fatalf("upload: %v", err)
	}
	if len(*keys) != 1 || (*keys)[0] != seeded {
		t.Fatalf("seeded key not preserved on the wire: %v", *keys)
	}
}

func TestUploadResendsFullBodyOnRetry(t *testing.T) {
	saved := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { retryDelays = saved }()

	var mu sync.Mutex
	var keys []string
	var bodyLens []int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var key string
		if metaB64 := r.Header.Get(HeaderCliMetadata); metaB64 != "" {
			if metaJSON, err := base64.StdEncoding.DecodeString(metaB64); err == nil {
				var req CLIRequest
				if json.Unmarshal(metaJSON, &req) == nil {
					key = req.Options["upload_idempotency_key"]
				}
			}
		}
		mu.Lock()
		keys = append(keys, key)
		bodyLens = append(bodyLens, len(body))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(503)
		fmt.Fprint(w, `{"success":false,"message":"scanner unavailable"}`)
	}))
	defer srv.Close()

	client := &Client{httpClient: srv.Client(), endpoint: srv.URL, apiKey: "test"}
	content := "the-complete-upload-body"
	localPath := writeTempFile(t, content)

	if _, err := client.Upload(context.Background(), localPath, "/dst", nil); err == nil {
		t.Fatal("503 upload should have returned an error after retries")
	}

	if len(bodyLens) != 3 {
		t.Fatalf("got %d attempts, want 3", len(bodyLens))
	}
	for i, n := range bodyLens {
		if n != len(content) {
			t.Errorf("attempt %d sent %d body bytes, want %d (reader not re-opened)", i, n, len(content))
		}
	}
	if keys[0] == "" || keys[0] != keys[1] || keys[1] != keys[2] {
		t.Errorf("idempotency key not stable across retries: %v", keys)
	}
}
