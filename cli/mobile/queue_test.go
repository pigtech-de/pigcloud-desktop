package mobile

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
)

func coded(kind api.ErrorKind, status int, code string, retryAfter time.Duration) error {
	return &api.RequestError{Kind: kind, StatusCode: status, RetryAfter: retryAfter, Err: &api.APIError{Code: code, Message: "refused"}}
}

func TestClassifyUploadSeparatesShedQuotaAndTransient(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		class      string
		code       string
		retryAfter time.Duration
	}{
		{"chunked storage limit answered at 200", coded(api.KindTransient, 200, "storage_limit", 0), ErrorClassQuota, "storage_limit", 0},
		{"cli storage limit answered 409", coded(api.KindPermanent, 409, "storage_limit", 0), ErrorClassQuota, "storage_limit", 0},
		{"daily allowance spent", coded(api.KindRateLimited, 429, "daily_limit", 0), ErrorClassDailyLimit, "daily_limit", 0},
		{"admission shed with retry-after", coded(api.KindRateLimited, 429, "too_many_concurrent", 7*time.Second), ErrorClassShed, "too_many_concurrent", 7 * time.Second},
		{"scanner shed at 503", coded(api.KindTransient, 503, "scanner_busy", 2*time.Second), ErrorClassShed, "scanner_busy", 2 * time.Second},
		{"bare 503", coded(api.KindTransient, 503, "", 30*time.Second), ErrorClassShed, "", 30 * time.Second},
		{"bare 429", coded(api.KindRateLimited, 429, "", 0), ErrorClassShed, "", 0},
		{"spent scan budget", coded(api.KindRateLimited, 429, "rate_limited", 3000*time.Second), ErrorClassRateLimited, "rate_limited", 3000 * time.Second},
		{"spent scan budget past its window", coded(api.KindRateLimited, 429, "rate_limited", 3*time.Hour), ErrorClassRateLimited, "rate_limited", time.Hour},
		{"spent scan budget without a hint", coded(api.KindRateLimited, 429, "rate_limited", 0), ErrorClassRateLimited, "rate_limited", time.Minute},
		{"bad gateway", coded(api.KindTransient, 502, "", 0), ErrorClassTransient, "", 0},
		{"unsanitizable file", coded(api.KindPermanent, 422, "sanitize_failed", 0), ErrorClassPermanent, "sanitize_failed", 0},
		{"uncoded conflict", coded(api.KindPermanent, 409, "", 0), ErrorClassPermanent, "", 0},
		{"revoked credential", coded(api.KindPermanent, 401, "", 0), ErrorClassUnauthorized, "", 0},
		{"forbidden", coded(api.KindPermanent, 403, "", 0), ErrorClassUnauthorized, "", 0},
		{"host cancelled", fmt.Errorf("upload: %w", context.Canceled), ErrorClassCancelled, "", 0},
		{"photo deleted under the queue", fmt.Errorf("open: %w", fs.ErrNotExist), ErrorClassLocal, "", 0},
		{"grant revoked under the queue", fmt.Errorf("open: %w", fs.ErrPermission), ErrorClassLocal, "", 0},
		{"traversing name", badInputError{errors.New("file_name must be a bare name")}, ErrorClassPermanent, "", 0},
		{"unclassified network fault", errors.New("request failed: connection reset"), ErrorClassTransient, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyUpload(tc.err)
			if got.class != tc.class {
				t.Errorf("class = %q, want %q", got.class, tc.class)
			}
			if got.code != tc.code {
				t.Errorf("code = %q, want %q", got.code, tc.code)
			}
			if got.retryAfter != tc.retryAfter {
				t.Errorf("retryAfter = %s, want %s", got.retryAfter, tc.retryAfter)
			}
		})
	}
}

type fakeServer struct {
	mu       sync.Mutex
	commands []api.CLIRequest
	ul       func(w http.ResponseWriter)
	mk       func(w http.ResponseWriter)
}

func (f *fakeServer) recorded() []api.CLIRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]api.CLIRequest(nil), f.commands...)
}

func startFakeServer(t *testing.T, f *fakeServer) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("action") {
		case "tee-attestation":
			fmt.Fprint(w, `{"success":true,"enabled":false,"available":false}`)
			return
		case "cli":
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var req api.CLIRequest
		if meta := r.Header.Get(api.HeaderCliMetadata); meta != "" {
			raw, _ := base64.StdEncoding.DecodeString(meta)
			_ = json.Unmarshal(raw, &req)
			_, _ = io.Copy(io.Discard, r.Body)
		} else {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &req)
		}
		f.mu.Lock()
		f.commands = append(f.commands, req)
		f.mu.Unlock()
		switch req.Command {
		case "ul":
			f.ul(w)
		case "mk":
			f.mk(w)
		default:
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"success":false}`)
		}
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL + "/cloud/actions.php"
}

func uploadOnce(t *testing.T, s *Session, dir string) uploadResult {
	t.Helper()
	local := filepath.Join(dir, "IMG_0001.heic")
	if err := os.WriteFile(local, []byte("an original, never transcoded"), 0o600); err != nil {
		t.Fatalf("write local: %v", err)
	}
	req, err := json.Marshal(uploadRequest{LocalPath: local, RemoteDir: "/Camera roll/Pixel", FileName: "IMG_0001.heic"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := s.Upload(string(req), nil)
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	var result uploadResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	return result
}

func TestUploadResultCarriesTheNodeIDAndTheErrorClass(t *testing.T) {
	cases := []struct {
		name       string
		reply      func(w http.ResponseWriter)
		ok         bool
		nodeID     string
		class      string
		code       string
		retryAfter int64
		retryable  bool
	}{
		{
			name: "stored",
			reply: func(w http.ResponseWriter) {
				fmt.Fprint(w, `{"success":true,"node_id":"0a1b2c3d4e5f60718293a4b5c6d7e8f9"}`)
			},
			ok:     true,
			nodeID: "0a1b2c3d4e5f60718293a4b5c6d7e8f9",
		},
		{
			name: "storage full",
			reply: func(w http.ResponseWriter) {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprint(w, `{"success":false,"message":"Storage limit exceeded","errorCode":"storage_limit"}`)
			},
			class: ErrorClassQuota, code: "storage_limit",
		},
		{
			name: "admission shed",
			reply: func(w http.ResponseWriter) {
				w.Header().Set("Retry-After", "7")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"success":false,"message":"Too many uploads","errorCode":"too_many_concurrent"}`)
			},
			class: ErrorClassShed, code: "too_many_concurrent", retryAfter: 7, retryable: true,
		},
		{
			name: "spent scan budget",
			reply: func(w http.ResponseWriter) {
				w.Header().Set("Retry-After", "1800")
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"success":false,"message":"Hourly upload limit reached.","errorCode":"rate_limited","retryAfter":1800,"bucket":"tee_scan"}`)
			},
			class: ErrorClassRateLimited, code: "rate_limited", retryAfter: 1800, retryable: true,
		},
		{
			name: "daily allowance refused at 200",
			reply: func(w http.ResponseWriter) {
				fmt.Fprint(w, `{"success":false,"message":"Daily limit","errorCode":"daily_limit"}`)
			},
			class: ErrorClassDailyLimit, code: "daily_limit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, dir := newTestSession(t)
			if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
				t.Fatalf("Unlock: %v", err)
			}
			startFakeServer(t, &fakeServer{ul: tc.reply})

			result := uploadOnce(t, s, dir)
			if result.OK != tc.ok {
				t.Fatalf("ok = %v, want %v (%s)", result.OK, tc.ok, result.Message)
			}
			if result.NodeID != tc.nodeID {
				t.Errorf("node_id = %q, want %q", result.NodeID, tc.nodeID)
			}
			if result.ErrorClass != tc.class || result.ErrorCode != tc.code {
				t.Errorf("class/code = %q/%q, want %q/%q", result.ErrorClass, result.ErrorCode, tc.class, tc.code)
			}
			if result.RetryAfterSeconds != tc.retryAfter {
				t.Errorf("retry_after_seconds = %d, want %d", result.RetryAfterSeconds, tc.retryAfter)
			}
			if result.Retryable != tc.retryable {
				t.Errorf("retryable = %v, want %v", result.Retryable, tc.retryable)
			}
			if !tc.ok && result.Cursor == "" {
				t.Error("a refused upload returned no cursor to resume from")
			}
		})
	}
}

func TestEnsureFolderSealsEverySegmentAndSurvivesAnExistingFolder(t *testing.T) {
	s, _ := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fake := &fakeServer{mk: func(w http.ResponseWriter) { fmt.Fprint(w, `{"success":true,"path":"/Camera roll/Pixel/DCIM"}`) }}
	startFakeServer(t, fake)

	out, err := s.EnsureFolder("/Camera roll/Pixel/DCIM")
	if err != nil {
		t.Fatalf("EnsureFolder: %v", err)
	}
	var result folderResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	if !result.OK {
		t.Fatalf("EnsureFolder reported %+v", result)
	}
	commands := fake.recorded()
	if len(commands) != 1 || commands[0].Command != "mk" {
		t.Fatalf("server saw %+v, want one mk", commands)
	}
	options := commands[0].Options
	if options["parents"] != "true" {
		t.Error("mk without parents fails on the first upload of a fresh device folder")
	}
	var segments []map[string]string
	if err := json.Unmarshal([]byte(options["e2ee_path_segments"]), &segments); err != nil {
		t.Fatalf("e2ee_path_segments %q: %v", options["e2ee_path_segments"], err)
	}
	if len(segments) != 3 {
		t.Fatalf("sealed %d segments, want 3", len(segments))
	}
	for i, segment := range segments {
		if segment["e2ee_display_name"] == "" || segment["e2ee_path_token"] == "" {
			t.Errorf("segment %d went up without its sealed name: %v", i, segment)
		}
	}
}

func TestEnsureFolderReportsAShedAndRefusesATraversal(t *testing.T) {
	s, _ := newTestSession(t)
	if err := s.Unlock(newKeyBlob(t, "correct horse battery staple")); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	fake := &fakeServer{mk: func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"success":false,"message":"slow down"}`)
	}}
	startFakeServer(t, fake)

	out, err := s.EnsureFolder("/Camera roll/Pixel")
	if err != nil {
		t.Fatalf("EnsureFolder: %v", err)
	}
	var result folderResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("parse %q: %v", out, err)
	}
	if result.OK || result.ErrorClass != ErrorClassShed {
		t.Errorf("a 429 read as %+v, want a shed", result)
	}

	before := len(fake.recorded())
	if _, err := s.EnsureFolder("/Camera roll/../Documents"); err == nil {
		t.Error("a parent segment was accepted")
	}
	if len(fake.recorded()) != before {
		t.Error("a refused folder still reached the server")
	}
}

func TestSweepStagingExceptKeepsTheCiphertextAHeldCursorNames(t *testing.T) {
	s, dir := newTestSession(t)
	cache := filepath.Join(dir, "cache")
	held := filepath.Join(cache, stagingPrefix+"held")
	orphan := filepath.Join(cache, stagingPrefix+"orphan")
	for _, p := range []string{held, orphan} {
		if err := os.WriteFile(p, []byte("ciphertext"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	cursor, err := json.Marshal(uploadCursor{EncryptedPath: held, RemoteDir: "/", FileName: "a.jpg"})
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	outside, err := json.Marshal(uploadCursor{EncryptedPath: filepath.Join(dir, "elsewhere"), RemoteDir: "/", FileName: "b.jpg"})
	if err != nil {
		t.Fatalf("marshal cursor: %v", err)
	}
	keep, err := json.Marshal([]string{string(cursor), string(outside), "not a cursor"})
	if err != nil {
		t.Fatalf("marshal keep: %v", err)
	}

	removed, err := s.SweepStagingExcept(string(keep))
	if err != nil {
		t.Fatalf("SweepStagingExcept: %v", err)
	}
	if removed != 1 {
		t.Errorf("removed %d files, want the one orphan", removed)
	}
	if _, err := os.Stat(held); err != nil {
		t.Error("the sweep deleted ciphertext a stored cursor still names, so the resume re-encrypts")
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Error("the orphan survived the sweep")
	}
	if _, err := s.SweepStagingExcept("not json"); err == nil {
		t.Error("garbage keep list accepted")
	}
}
