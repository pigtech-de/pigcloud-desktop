package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func uploadTestServer(t *testing.T) (*Client, func(status int, body string), *[]string) {
	t.Helper()
	var mu sync.Mutex
	status := 200
	body := `{"success":true}`
	var keys []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if metaB64 := r.Header.Get(HeaderCliMetadata); metaB64 != "" {
			if metaJSON, err := base64.StdEncoding.DecodeString(metaB64); err == nil {
				var req CLIRequest
				if json.Unmarshal(metaJSON, &req) == nil {
					keys = append(keys, req.Options["upload_idempotency_key"])
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)

	set := func(s int, b string) {
		mu.Lock()
		defer mu.Unlock()
		status, body = s, b
		keys = keys[:0]
	}
	client := &Client{httpClient: srv.Client(), endpoint: srv.URL, apiKey: "test"}
	return client, set, &keys
}

func TestUploadClassifiesRejections(t *testing.T) {
	saved := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { retryDelays = saved }()

	client, set, keys := uploadTestServer(t)
	localPath := filepath.Join(t.TempDir(), "f.txt")
	if err := os.WriteFile(localPath, []byte("payload"), 0600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	upload := func() (*Response, error) {
		return client.Upload(context.Background(), localPath, "/dst", nil)
	}

	set(400, `{"success":false,"message":"rejected name","errorCode":"bad_name"}`)
	resp, err := upload()
	if resp != nil || err == nil {
		t.Fatalf("400: want classified error, got resp=%v err=%v", resp, err)
	}
	if !IsPermanent(err) || IsRateLimited(err) || IsTransient(err) {
		t.Errorf("400 not classified permanent: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "bad_name" || apiErr.Message != "rejected name" {
		t.Errorf("400 lost code/message: %v", err)
	}
	if len(*keys) != 1 {
		t.Errorf("400 retried: %d requests", len(*keys))
	}

	set(429, `{"success":false,"message":"daily limit"}`)
	if _, err := upload(); !IsRateLimited(err) || IsPermanent(err) {
		t.Errorf("429 not classified rate-limited: %v", err)
	}
	if len(*keys) != 1 {
		t.Errorf("429 retried on the short loop: %d requests", len(*keys))
	}

	set(503, `{"success":false,"message":"scanner unavailable"}`)
	if _, err := upload(); !IsTransient(err) || IsPermanent(err) {
		t.Errorf("503 not classified transient: %v", err)
	}
	if len(*keys) != 3 {
		t.Fatalf("503: want 3 attempts, got %d", len(*keys))
	}
	if (*keys)[0] == "" || (*keys)[0] != (*keys)[1] || (*keys)[1] != (*keys)[2] {
		t.Errorf("idempotency key changed across transport retries: %v", *keys)
	}

	set(200, `{"success":false,"message":"odd rejection"}`)
	resp, err = upload()
	if err != nil || resp == nil || resp.Success {
		t.Fatalf("200 rejection: want resp with success=false, got resp=%v err=%v", resp, err)
	}

	set(200, `{"success":true}`)
	resp, err = upload()
	if err != nil || resp == nil || !resp.Success {
		t.Fatalf("200 success: got resp=%v err=%v", resp, err)
	}
}
