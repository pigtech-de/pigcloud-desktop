package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const cloudflare413 = `<html><head><title>413 Request Entity Too Large</title></head>` +
	`<body><center><h1>413 Request Entity Too Large</h1></center>` +
	`<hr><center>cloudflare</center></body></html>`

type edgeCappedServer struct {
	mu sync.Mutex

	edgeCap         int64
	originStatus    int
	originBody      string
	finalizeBody    string
	finalizeStatus  int
	finalizePending int
	finalizeBusy    int
	finalizeCalls   int
	chunkFailIndex int
	chunkFailBody  string

	csrfIssued    int
	edgeRejects   int
	singleBodies  int
	chunkRequests int

	sessions     map[string]map[int][]byte
	uploadedIdx  []int
	chunkIDs     []string
	legacyTokens []string
	totalChunks  int
	finalizeVal  url.Values
	committed    []byte
	sawCookie    bool
}

func newEdgeCappedServer(t *testing.T, edgeCap int64) (*Client, *edgeCappedServer) {
	t.Helper()
	s := &edgeCappedServer{edgeCap: edgeCap, sessions: map[string]map[int][]byte{}, chunkFailIndex: -1}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return &Client{httpClient: srv.Client(), endpoint: srv.URL, apiKey: "test"}, s
}

func (s *edgeCappedServer) staged(chunkID string) map[int][]byte {
	if s.sessions[chunkID] == nil {
		s.sessions[chunkID] = map[int][]byte{}
	}
	return s.sessions[chunkID]
}

func (s *edgeCappedServer) distinctChunkIDs() []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range s.chunkIDs {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

func (s *edgeCappedServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.edgeCap > 0 && r.ContentLength > s.edgeCap {
		s.mu.Lock()
		s.edgeRejects++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		io.WriteString(w, cloudflare413)
		return
	}

	if r.URL.Query().Get("action") == "auth-csrf" {
		s.mu.Lock()
		s.csrfIssued++
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "sess-1", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"csrfToken":"csrf-token-1"}`)
		return
	}

	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		s.serveChunk(w, r)
		return
	}

	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.singleBodies++
	s.committed = body
	status, origin := s.originStatus, s.originBody
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if status != 0 {
		w.WriteHeader(status)
		io.WriteString(w, origin)
		return
	}
	io.WriteString(w, `{"success":true,"name":"f.bin","storedPath":"/dst/f.bin"}`)
}

func (s *edgeCappedServer) serveChunk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(8 << 20); err != nil {
		http.Error(w, "bad multipart", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := r.Cookie("PHPSESSID"); err == nil {
		s.sawCookie = true
	}
	if r.FormValue("csrf_token") == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"success":false,"error":"invalid csrf"}`)
		return
	}
	if id := r.FormValue("chunkUploadId"); id != "" {
		s.chunkIDs = append(s.chunkIDs, id)
	}
	w.Header().Set("Content-Type", "application/json")

	if r.FormValue("action") == "check-upload-chunks" {
		s.writeProbe(w, r.FormValue("chunkUploadId"))
		return
	}
	if r.FormValue("action") != "upload" {
		http.Error(w, "wrong action", http.StatusBadRequest)
		return
	}
	s.chunkRequests++

	if r.FormValue("finalize") == "1" {
		s.finalizeVal = url.Values{}
		maps.Copy(s.finalizeVal, r.MultipartForm.Value)
		staged := s.staged(r.FormValue("chunkUploadId"))
		idx := make([]int, 0, len(staged))
		for i := range staged {
			idx = append(idx, i)
		}
		sort.Ints(idx)
		var stitched bytes.Buffer
		for _, i := range idx {
			stitched.Write(staged[i])
		}
		s.committed = stitched.Bytes()
		s.finalizeCalls++
		if s.finalizePending > 0 {
			s.finalizePending--
			w.WriteHeader(http.StatusAccepted)
			io.WriteString(w, `{"success":false,"errorCode":"scan_pending","pending":true,"retryAfterMs":5,"error":"still scanning"}`)
			return
		}
		if s.finalizeBusy > 0 {
			s.finalizeBusy--
			w.WriteHeader(http.StatusTooManyRequests)
			io.WriteString(w, `{"success":false,"errorCode":"scanner_busy","error":"scanner busy"}`)
			return
		}
		if s.finalizeBody != "" {
			if s.finalizeStatus != 0 {
				w.WriteHeader(s.finalizeStatus)
			}
			io.WriteString(w, s.finalizeBody)
			return
		}
		io.WriteString(w, `{"success":true,"storedFilename":"f.bin","nodeId":"abc123","storage":{"usedBytes":1,"limitBytes":2}}`)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "no file part", http.StatusBadRequest)
		return
	}
	defer file.Close()
	part, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "read part", http.StatusBadRequest)
		return
	}
	index, err := strconv.Atoi(r.FormValue("chunkIndex"))
	if err != nil {
		http.Error(w, "bad chunkIndex", http.StatusBadRequest)
		return
	}
	s.legacyTokens = append(s.legacyTokens, r.FormValue("path_tokens_legacy"))
	if index == s.chunkFailIndex {
		io.WriteString(w, s.chunkFailBody)
		return
	}
	s.staged(r.FormValue("chunkUploadId"))[index] = part
	s.uploadedIdx = append(s.uploadedIdx, index)
	s.totalChunks, _ = strconv.Atoi(r.FormValue("totalChunks"))
	fmt.Fprintf(w, `{"success":true,"chunkReceived":true,"chunkIndex":%d}`, index)
}

func fastUploadRetries(t *testing.T) {
	t.Helper()
	savedDelays, savedRate := retryDelays, rateLimitWait
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	rateLimitWait = func(int, time.Duration) time.Duration { return time.Millisecond }
	t.Cleanup(func() { retryDelays, rateLimitWait = savedDelays, savedRate })
}

func (s *edgeCappedServer) writeProbe(w http.ResponseWriter, chunkID string) {
	staged := s.staged(chunkID)
	idx := make([]int, 0, len(staged))
	for i := range staged {
		idx = append(idx, i)
	}
	sort.Ints(idx)

	contiguous := true
	for i, v := range idx {
		if i != v {
			contiguous = false
			break
		}
	}
	var parts []string
	if contiguous && len(idx) > 0 {
		for _, i := range idx {
			parts = append(parts, strconv.Itoa(len(staged[i])))
		}
		fmt.Fprintf(w, `{"success":true,"received":[%s]}`, strings.Join(parts, ","))
		return
	}
	for _, i := range idx {
		parts = append(parts, fmt.Sprintf(`"%d":%d`, i, len(staged[i])))
	}
	fmt.Fprintf(w, `{"success":true,"received":{%s}}`, strings.Join(parts, ","))
}

func writeRandomFile(t *testing.T, size int) (string, []byte) {
	t.Helper()
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	p := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(p, buf, 0600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p, buf
}

func TestUploadWireName(t *testing.T) {
	cases := map[string]string{
		"report.pdf":          "f.pdf",
		"Quarterly FINAL.PDF": "f.pdf",
		"archive.tar.gz":      "f.gz",
		"Makefile":            "f",
		".gitignore":          "f",
		"trailing.":           "f.",
	}
	for name, want := range cases {
		if got := uploadWireName(name); got != want {
			t.Errorf("uploadWireName(%q) = %q, want %q", name, got, want)
		}
	}
}

func e2eeUploadOpts() map[string]string {
	return map[string]string{
		"_original_name":     "report.pdf",
		"sealed_key":         "c2VhbGVk",
		"encryption_meta":    "bWV0YQ==",
		"tee_sealed_key":     "dGVl",
		"plaintext_hmac":     "aG1hYw==",
		"e2ee_display_name":  "ZGlzcGxheQ==",
		"e2ee_path_token":    "deadbeef",
		"path_tokens":        `{"dst":"aa"}`,
		"signature_ed25519":  "c2lnZWQ=",
		"signature_mldsa":    "c2lnbWw=",
		"signing_pk_ed25519": "cGtlZA==",
		"signing_pk_mldsa":   "cGttbA==",
		"source_mtime":       "1700000000",
	}
}

func TestUploadChunksPastEdgeBodyCap(t *testing.T) {
	savedSingle, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<20, 256<<10
	defer func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk }()

	client, srv := newEdgeCappedServer(t, 1<<20)
	localPath, want := writeRandomFile(t, 3<<20)

	var lastSent, lastTotal int64
	resp, err := client.Upload(context.Background(), localPath, "/dst", func(sent, total int64) {
		lastSent, lastTotal = sent, total
	}, e2eeUploadOpts())
	if err != nil {
		t.Fatalf("upload over the edge cap failed: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("upload did not succeed: %+v", resp)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.edgeRejects != 0 {
		t.Errorf("client still posted %d oversized bodies through the edge", srv.edgeRejects)
	}
	if !bytes.Equal(srv.committed, want) {
		t.Errorf("stitched upload is %d bytes, want %d", len(srv.committed), len(want))
	}
	if srv.totalChunks != 12 {
		t.Errorf("totalChunks = %d, want 12", srv.totalChunks)
	}
	if !srv.sawCookie {
		t.Error("chunk requests carried no session cookie")
	}
	if lastSent != int64(len(want)) || lastTotal != int64(len(want)) {
		t.Errorf("progress ended at %d/%d, want %d/%d", lastSent, lastTotal, len(want), len(want))
	}

	fin := srv.finalizeVal
	for field, want := range map[string]string{
		"path":                 "/dst",
		"originalName":         "f.pdf",
		"totalSize":            strconv.Itoa(3 << 20),
		"finalize":             "1",
		"csrf_token":           "csrf-token-1",
		"e2ee_sealed_key":      "c2VhbGVk",
		"e2ee_encryption_meta": "bWV0YQ==",
		"e2ee_tee_sealed_key":  "dGVl",
		"e2ee_plaintext_hmac":  "aG1hYw==",
		"e2ee_display_name":    "ZGlzcGxheQ==",
		"e2ee_path_token":      "deadbeef",
		"path_tokens":          `{"dst":"aa"}`,
		"signature_ed25519":    "c2lnZWQ=",
		"signature_mldsa":      "c2lnbWw=",
		"signing_pk_ed25519":   "cGtlZA==",
		"signing_pk_mldsa":     "cGttbA==",
		"source_mtime":         "1700000000",
		"conflict_strategy":    "replace",
	} {
		if got := fin.Get(field); got != want {
			t.Errorf("finalize %s = %q, want %q", field, got, want)
		}
	}
	if fin.Get("upload_idempotency_key") == "" {
		t.Error("finalize carried no upload_idempotency_key")
	}
	if fin.Get("_original_name") != "" {
		t.Error("internal _original_name option leaked onto the wire")
	}
}

func TestUploadFallsBackToChunksOn413(t *testing.T) {
	savedChunk := uploadChunkSize
	uploadChunkSize = 256 << 10
	defer func() { uploadChunkSize = savedChunk }()

	client, srv := newEdgeCappedServer(t, 512<<10)
	localPath, want := writeRandomFile(t, 1<<20)

	resp, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
	if err != nil {
		t.Fatalf("upload did not fall back to chunks: %v", err)
	}
	if resp == nil || !resp.Success {
		t.Fatalf("upload did not succeed: %+v", resp)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.edgeRejects != 1 {
		t.Errorf("whole-body attempt hit the edge %d times, want exactly 1", srv.edgeRejects)
	}
	if srv.singleBodies != 0 {
		t.Errorf("%d whole-body uploads reached the origin", srv.singleBodies)
	}
	if !bytes.Equal(srv.committed, want) {
		t.Errorf("stitched upload is %d bytes, want %d", len(srv.committed), len(want))
	}
}

func TestUploadClassifiesChunkedRejectionsFromBody(t *testing.T) {
	savedSingle, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	defer func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk }()
	fastUploadRetries(t)

	t.Run("finalize rejection at 200 stays retryable", func(t *testing.T) {
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizeBody = `{"success":false,"error":"Another request is combining these chunks right now."}`
		localPath, _ := writeRandomFile(t, 16<<10)

		_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err == nil {
			t.Fatal("a rejected upload must return a classified error, not a bare response")
		}
		if IsPermanent(err) {
			t.Errorf("a 200 rejection latched permanent, and nothing can requeue it: %v", err)
		}
		if !IsTransient(err) {
			t.Errorf("a 200 rejection must ride the bounded retry ladder: %v", err)
		}
		if !strings.Contains(err.Error(), "combining these chunks") {
			t.Errorf("server message lost: %v", err)
		}
	})

	t.Run("chunk rejection at 200 stays retryable", func(t *testing.T) {
		client, srv := newEdgeCappedServer(t, 0)
		srv.chunkFailIndex = 1
		srv.chunkFailBody = `{"success":false,"error":"Scanner temporarily unavailable."}`
		localPath, _ := writeRandomFile(t, 16<<10)

		_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err == nil {
			t.Fatal("a rejected part must fail the upload")
		}
		if IsPermanent(err) || !IsTransient(err) {
			t.Errorf("chunk rejection must stay retryable: %v", err)
		}
	})

	t.Run("a server-marked code still latches", func(t *testing.T) {
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizeBody = `{"success":false,"error":"A file named report.pdf already exists.","errorCode":"duplicate"}`
		localPath, _ := writeRandomFile(t, 16<<10)

		_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err == nil || !IsPermanent(err) {
			t.Errorf("a name collision is not fixed by waiting: %v", err)
		}
	})

	t.Run("an explicit status still governs", func(t *testing.T) {
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizeBody = `{"success":false,"error":"busy"}`
		srv.finalizeStatus = http.StatusServiceUnavailable
		localPath, _ := writeRandomFile(t, 16<<10)

		_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err == nil || !IsTransient(err) || IsPermanent(err) {
			t.Errorf("503 must stay transient: %v", err)
		}
	})
}

func TestChunkedFinalizeWaitsOutTheScan(t *testing.T) {
	savedSingle, savedChunk, savedWait := uploadSingleBodyMaxBytes, uploadChunkSize, scanPendingMaxWait
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	defer func() {
		uploadSingleBodyMaxBytes, uploadChunkSize, scanPendingMaxWait = savedSingle, savedChunk, savedWait
	}()

	t.Run("polls until the verdict lands", func(t *testing.T) {
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizePending = 3
		localPath, want := writeRandomFile(t, 16<<10)

		resp, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err != nil || resp == nil || !resp.Success {
			t.Fatalf("a scan that finishes must commit: resp=%+v err=%v", resp, err)
		}
		if srv.finalizeCalls != 4 {
			t.Errorf("finalize must be resent once per 202 and once to settle, got %d", srv.finalizeCalls)
		}
		if ids := srv.distinctChunkIDs(); len(ids) != 1 {
			t.Errorf("a pending scan must not reopen the staging session, saw %d sessions", len(ids))
		}
		if !bytes.Equal(srv.committed, want) {
			t.Errorf("the settled finalize must commit the parts already staged")
		}
	})

	t.Run("gives up on the wall clock as a transient failure", func(t *testing.T) {
		scanPendingMaxWait = 0
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizePending = 100
		localPath, _ := writeRandomFile(t, 16<<10)

		_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err == nil || !IsTransient(err) {
			t.Fatalf("an unfinished scan is retried later by the caller, not latched: %v", err)
		}
		if srv.finalizeCalls > 2 {
			t.Errorf("an expired deadline must stop polling, got %d finalizes", srv.finalizeCalls)
		}
	})
}

func TestChunkedFinalizeWaitsOutAScannerShed(t *testing.T) {
	savedSingle, savedChunk, savedWait, savedDefault := uploadSingleBodyMaxBytes, uploadChunkSize, scanPendingMaxWait, scanPendingDefaultWait
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	scanPendingDefaultWait = time.Millisecond
	defer func() {
		uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk
		scanPendingMaxWait, scanPendingDefaultWait = savedWait, savedDefault
	}()

	t.Run("resends the same finalize until the scanner takes it", func(t *testing.T) {
		fastUploadRetries(t)
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizeBusy = 1
		localPath, want := writeRandomFile(t, 16<<10)

		resp, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err != nil || resp == nil || !resp.Success {
			t.Fatalf("a shed must be waited out, not latched: resp=%+v err=%v", resp, err)
		}
		if srv.finalizeCalls != 2 {
			t.Errorf("one shed must cost exactly one resend, not a rate-limit ladder, got %d finalizes", srv.finalizeCalls)
		}
		if ids := srv.distinctChunkIDs(); len(ids) != 1 {
			t.Errorf("a shed must not reopen the staging session, saw %d sessions", len(ids))
		}
		if !bytes.Equal(srv.committed, want) {
			t.Errorf("the settled finalize must commit the parts already staged")
		}
	})

	t.Run("gives up on the wall clock as a transient failure", func(t *testing.T) {
		fastUploadRetries(t)
		scanPendingMaxWait = 0
		client, srv := newEdgeCappedServer(t, 0)
		srv.finalizeBusy = 100
		localPath, _ := writeRandomFile(t, 16<<10)

		_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
		if err == nil || !IsTransient(err) {
			t.Fatalf("a scanner that stays busy is retried later by the caller, not latched: %v", err)
		}
	})
}

func TestUploadNeverSplicesAcrossAttempts(t *testing.T) {
	savedSingle, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	defer func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk }()
	fastUploadRetries(t)

	client, srv := newEdgeCappedServer(t, 0)
	srv.chunkFailIndex = 2
	srv.chunkFailBody = `{"success":false,"error":"Scanner temporarily unavailable."}`

	firstCiphertext, c1 := writeRandomFile(t, 16<<10)
	secondCiphertext, c2 := writeRandomFile(t, 16<<10)
	if bytes.Equal(c1, c2) {
		t.Fatal("fixture ciphertexts must differ")
	}

	opts := e2eeUploadOpts()
	opts["upload_idempotency_key"] = "stable-key-1"
	if _, err := client.Upload(context.Background(), firstCiphertext, "/dst", nil, opts); err == nil {
		t.Fatal("attempt 1 should fail at the rejected part")
	}
	srv.mu.Lock()
	staged := len(srv.uploadedIdx)
	srv.chunkFailIndex = -1
	srv.mu.Unlock()
	if staged == 0 {
		t.Fatal("attempt 1 staged nothing, so there is no carry-over to test")
	}

	opts2 := e2eeUploadOpts()
	opts2["upload_idempotency_key"] = "stable-key-1"
	if _, err := client.Upload(context.Background(), secondCiphertext, "/dst", nil, opts2); err != nil {
		t.Fatalf("attempt 2: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if !bytes.Equal(srv.committed, c2) {
		carried := 0
		for i := 0; i < len(srv.committed) && i < len(c1); i++ {
			if srv.committed[i] != c1[i] {
				break
			}
			carried++
		}
		t.Fatalf("committed blob is NOT attempt 2's ciphertext: %d bytes, %d carried over from attempt 1",
			len(srv.committed), carried)
	}
	if ids := srv.distinctChunkIDs(); len(ids) < 2 {
		t.Errorf("both attempts shared staging session %v; a re-encrypted retry must not inherit staged parts", ids)
	}
}

func TestUploadChunksCarryLegacyPathTokens(t *testing.T) {
	savedSingle, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	defer func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk }()

	client, srv := newEdgeCappedServer(t, 0)
	localPath, _ := writeRandomFile(t, 16<<10)

	opts := e2eeUploadOpts()
	opts["path_tokens_legacy"] = `{"dst":"bb"}`
	if _, err := client.Upload(context.Background(), localPath, "/dst", nil, opts); err != nil {
		t.Fatalf("upload: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.legacyTokens) == 0 {
		t.Fatal("no chunk PUTs recorded")
	}
	for i, got := range srv.legacyTokens {
		if got != `{"dst":"bb"}` {
			t.Errorf("chunk %d path_tokens_legacy = %q, want the caller's map", i, got)
		}
	}
	if srv.finalizeVal.Get("path_tokens_legacy") != `{"dst":"bb"}` {
		t.Errorf("finalize path_tokens_legacy = %q", srv.finalizeVal.Get("path_tokens_legacy"))
	}
}

func TestUploadForceRefusesCollisionInsteadOfServerNaming(t *testing.T) {
	savedSingle, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	defer func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk }()

	client, srv := newEdgeCappedServer(t, 0)
	srv.finalizeBody = `{"success":false,"error":"A file named report.pdf already exists.","errorCode":"duplicate","existingName":"report.pdf"}`
	localPath, _ := writeRandomFile(t, 8<<10)

	opts := e2eeUploadOpts()
	opts["force"] = "true"
	_, err := client.Upload(context.Background(), localPath, "/dst", nil, opts)
	if err == nil {
		t.Fatal("a blocked duplicate must return a classified error")
	}
	if !IsPermanent(err) {
		t.Errorf("a name collision is not fixed by retrying: %v", err)
	}

	srv.mu.Lock()
	strategy := srv.finalizeVal.Get("conflict_strategy")
	srv.mu.Unlock()
	if strategy != "block" {
		t.Errorf("conflict_strategy = %q with --force, want %q so the server never picks a name", strategy, "block")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "duplicate" {
		t.Errorf("errorCode lost: %v", err)
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("refusal does not tell the user what to do about --force: %q", err)
	}
}

func TestUploadKeepsOriginRejectionUnchunked(t *testing.T) {
	client, srv := newEdgeCappedServer(t, 0)
	srv.originStatus = http.StatusRequestEntityTooLarge
	srv.originBody = `{"success":false,"message":"File is too large. Maximum size is 5 GB."}`
	localPath, _ := writeRandomFile(t, 4096)

	_, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts())
	if err == nil {
		t.Fatal("origin 413 should surface as an error")
	}
	if !strings.Contains(err.Error(), "Maximum size is 5 GB") {
		t.Errorf("server's own message was replaced: %q", err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.chunkRequests != 0 {
		t.Errorf("re-sent the file as %d chunk requests after an origin 413", srv.chunkRequests)
	}
}

func TestUploadReusesOneSession(t *testing.T) {
	savedSingle, savedChunk := uploadSingleBodyMaxBytes, uploadChunkSize
	uploadSingleBodyMaxBytes, uploadChunkSize = 1<<10, 4<<10
	defer func() { uploadSingleBodyMaxBytes, uploadChunkSize = savedSingle, savedChunk }()

	client, srv := newEdgeCappedServer(t, 0)
	localPath, _ := writeRandomFile(t, 16<<10)

	for i := range 3 {
		if _, err := client.Upload(context.Background(), localPath, "/dst", nil, e2eeUploadOpts()); err != nil {
			t.Fatalf("upload %d: %v", i, err)
		}
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.csrfIssued != 1 {
		t.Errorf("opened %d upload sessions for 3 uploads, want 1", srv.csrfIssued)
	}
}

func TestUploadEdgeRejectionIsLegible(t *testing.T) {
	saved := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	defer func() { retryDelays = saved }()

	client, _ := newEdgeCappedServer(t, 16)
	localPath, _ := writeRandomFile(t, 1024)

	_, err := client.Upload(context.Background(), localPath, "/dst", nil)
	if err == nil {
		t.Fatal("upload against a 16-byte edge cap should fail")
	}
	msg := err.Error()
	if strings.Contains(msg, "<html") || strings.Contains(msg, "<center>") {
		t.Errorf("raw HTML reached the user: %q", msg)
	}
	if strings.Contains(msg, "invalid character '<'") {
		t.Errorf("JSON parse noise reached the user: %q", msg)
	}
	if !strings.Contains(msg, "413") {
		t.Errorf("error does not name the status: %q", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "too large") {
		t.Errorf("error does not explain the rejection: %q", msg)
	}
	if !IsPermanent(err) {
		t.Errorf("413 should stay classified permanent: %v", err)
	}
}

type controllableTimer struct {
	fire  func()
	arms  atomic.Int64
	stops atomic.Int64
}

func (t *controllableTimer) Reset(time.Duration) bool { t.arms.Add(1); return true }
func (t *controllableTimer) Stop() bool               { t.stops.Add(1); return true }

func TestStalledChunkUploadIsCutOncePerAttempt(t *testing.T) {
	savedDelays := retryDelays
	retryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { retryDelays = savedDelays })

	var timerMu sync.Mutex
	var timers []*controllableTimer
	savedTimer := newStallTimer
	newStallTimer = func(_ time.Duration, fire func()) stallTimer {
		timer := &controllableTimer{fire: fire}
		timerMu.Lock()
		timers = append(timers, timer)
		timerMu.Unlock()
		return timer
	}
	t.Cleanup(func() { newStallTimer = savedTimer })
	tripNewest := func() {
		timerMu.Lock()
		timer := timers[len(timers)-1]
		timerMu.Unlock()
		timer.fire()
	}

	var mu sync.Mutex
	chunkAttempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "s", Path: "/"})
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"success":true,"csrfToken":"c"}`)
			return
		}
		io.Copy(io.Discard, r.Body)
		mu.Lock()
		chunkAttempts++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		io.WriteString(w, `{"suc`)
		w.(http.Flusher).Flush()
		tripNewest()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	src := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(src, bytes.Repeat([]byte("z"), 64), 0600); err != nil {
		t.Fatal(err)
	}
	client := &Client{
		httpClient: &http.Client{Transport: &http.Transport{ResponseHeaderTimeout: 10 * time.Second}},
		endpoint:   srv.URL,
		apiKey:     "k",
	}

	done := make(chan error, 1)
	go func() {
		_, err := client.uploadChunked(context.Background(), src, "/dst", 64, nil, map[string]string{"source": "big.bin"})
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("a stalled chunk upload never returned: nothing bounds inactivity")
	}

	if !errors.Is(err, errTransferStalled) {
		t.Fatalf("stalled chunk upload error = %v, want a stall", err)
	}
	mu.Lock()
	got := chunkAttempts
	mu.Unlock()
	if got != chunkUploadRetries {
		t.Errorf("server saw %d chunk attempts, want %d", got, chunkUploadRetries)
	}
	timerMu.Lock()
	guards := append([]*controllableTimer(nil), timers...)
	timerMu.Unlock()
	if len(guards) != chunkUploadRetries {
		t.Errorf("the ladder built %d stall guards for %d attempts: a later attempt reused a guard that had already fired",
			len(guards), chunkUploadRetries)
	}
	for i, guard := range guards {
		if arms := guard.arms.Load(); arms == 0 {
			t.Errorf("attempt %d never armed its stall window, so nothing bounded its inactivity", i+1)
		}
	}
}
