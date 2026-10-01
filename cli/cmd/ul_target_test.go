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
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
)

type recordingUploadServer struct {
	mu        sync.Mutex
	ulPaths   []string
	mkPaths   []string
	mkParents []string
	inPaths   []string
	commands  []string
	chunkPuts int
	inExists bool
}

func (s *recordingUploadServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		_ = r.ParseMultipartForm(1 << 20)
		s.mu.Lock()
		s.chunkPuts++
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"chunkReceived":true}`)
		return
	}
	if r.URL.Query().Get("action") == "auth-csrf" {
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "s", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true,"csrfToken":"tok"}`)
		return
	}

	var req api.CLIRequest
	if meta := r.Header.Get(api.HeaderCliMetadata); meta != "" {
		raw, err := base64.StdEncoding.DecodeString(meta)
		if err == nil {
			_ = json.Unmarshal(raw, &req)
		}
		_, _ = io.Copy(io.Discard, r.Body)
	} else {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
	}

	s.mu.Lock()
	s.commands = append(s.commands, req.Command)
	switch req.Command {
	case "ul":
		s.ulPaths = append(s.ulPaths, req.Options["target"])
	case "mk":
		s.mkPaths = append(s.mkPaths, req.Options["source"])
		s.mkParents = append(s.mkParents, req.Options["parents"])
	case "in":
		s.inPaths = append(s.inPaths, req.Options["source"])
	}
	exists := s.inExists
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	if req.Command == "in" && !exists {
		io.WriteString(w, `{"success":false,"message":"not found"}`)
		return
	}
	io.WriteString(w, `{"success":true,"name":"f.txt","storedPath":"/x/f.txt","storage":{"usedBytes":1,"limitBytes":2}}`)
}

func withTestEndpoint(t *testing.T, url string) {
	t.Helper()
	orig := config.GetConfigPath()
	path := filepath.Join(t.TempDir(), "config.json")
	body := `{"endpoint":` + strconv.Quote(url) + `,"api_key":"test-key","cwd":"/"}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	config.SetConfigFile(path)
	config.Load()
	t.Cleanup(func() {
		config.SetConfigFile(orig)
		config.Load()
	})
}

func TestRecursiveUploadTargetsParentDirectory(t *testing.T) {
	srv := &recordingUploadServer{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	localDir := filepath.Join(t.TempDir(), "payload")
	if err := os.MkdirAll(filepath.Join(localDir, "sub"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, rel := range []string{"root.txt", filepath.Join("sub", "nested.txt")} {
		if err := os.WriteFile(filepath.Join(localDir, rel), []byte("data"), 0600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	runRecursiveUpload(context.Background(), localDir, "/Backups")

	srv.mu.Lock()
	got := append([]string(nil), srv.ulPaths...)
	srv.mu.Unlock()
	sort.Strings(got)

	want := []string{"/Backups/payload", "/Backups/payload/sub"}
	if len(got) != len(want) {
		t.Fatalf("uploaded %d files, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("upload target %d = %q, want the parent directory %q", i, got[i], want[i])
		}
	}
}

func TestForceCollisionRefusedBeforeTransfer(t *testing.T) {
	srv := &recordingUploadServer{inExists: true}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	savedForce := ulForce
	ulForce = true
	defer func() { ulForce = savedForce }()

	localDir := filepath.Join(t.TempDir(), "payload")
	if err := os.MkdirAll(localDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.Create(filepath.Join(localDir, "big.bin"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(120 << 20); err != nil {
		f.Close()
		t.Fatalf("truncate: %v", err)
	}
	f.Close()
	if !api.UploadIsChunked(120 << 20) {
		t.Fatal("fixture is not above the chunk threshold")
	}

	runRecursiveUpload(context.Background(), localDir, "/Backups")

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if len(srv.ulPaths) != 0 {
		t.Errorf("transferred %d uploads before refusing the collision: %v", len(srv.ulPaths), srv.ulPaths)
	}
	if srv.chunkPuts != 0 {
		t.Errorf("sent %d chunk parts before refusing the collision", srv.chunkPuts)
	}
	if len(srv.inPaths) == 0 {
		t.Error("never probed for the collision")
	}
}

func TestRecursiveUploadCreatesEveryRemoteDirectoryWithParents(t *testing.T) {
	srv := &recordingUploadServer{}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	localDir := filepath.Join(t.TempDir(), "payload")
	if err := os.MkdirAll(filepath.Join(localDir, "sub", "deep"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(localDir, "sub", "deep", "f.txt"), []byte("data"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	runRecursiveUpload(context.Background(), localDir, "/Backups")

	srv.mu.Lock()
	paths := append([]string(nil), srv.mkPaths...)
	parents := append([]string(nil), srv.mkParents...)
	srv.mu.Unlock()

	want := []string{"/Backups/payload", "/Backups/payload/sub", "/Backups/payload/sub/deep"}
	if len(paths) != len(want) {
		t.Fatalf("mkdir calls = %v, want %v", paths, want)
	}
	for i := range want {
		if paths[i] != want[i] {
			t.Errorf("mkdir %d = %q, want %q (a parent created after its child cannot resolve)", i, paths[i], want[i])
		}
		if parents[i] != "true" {
			t.Errorf("mkdir %q sent parents=%q, want true", paths[i], parents[i])
		}
	}
}

func TestEnsureRemoteDirWireAndErrorContract(t *testing.T) {
	cases := []struct {
		name     string
		remote   string
		reply    string
		wantErr  bool
		wantText string
	}{
		{"the upload root", "/Backups/payload", `{"success":true}`, false, ""},
		{"a missing parent chain", "/Backups/payload/sub/deep", `{"success":true}`, false, ""},
		{
			"a directory that is already there",
			"/Backups/payload",
			`{"success":false,"message":"already exists","errorCode":"path_exists"}`,
			false, "",
		},
		{
			"a server-side refusal",
			"/Backups/payload",
			`{"success":false,"message":"permission denied"}`,
			true, "/Backups/payload",
		},
		{
			"a refusal that says nothing",
			"/Backups/payload",
			`{"success":false}`,
			true, "/Backups/payload",
		},
		{"an unreadable reply", "/Backups/payload", `not json`, true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sources, parents []string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				var req api.CLIRequest
				_ = json.Unmarshal(body, &req)
				if req.Command == "mk" {
					mu.Lock()
					sources = append(sources, req.Options["source"])
					parents = append(parents, req.Options["parents"])
					mu.Unlock()
				}
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, tc.reply)
			}))
			defer ts.Close()
			withTestEndpoint(t, ts.URL)

			err := ensureRemoteDir(context.Background(), api.NewClient(), tc.remote)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ensureRemoteDir error = %v, want error: %v", err, tc.wantErr)
			}
			if tc.wantText != "" && !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error %q does not name the directory it could not create (%q); "+
					"every file under it then fails one at a time with nothing pointing here",
					err, tc.wantText)
			}

			mu.Lock()
			defer mu.Unlock()
			if len(sources) != 1 || sources[0] != tc.remote {
				t.Fatalf("mk sources = %v, want exactly one for %q", sources, tc.remote)
			}
			if parents[0] != "true" {
				t.Errorf("mk sent parents=%q, want true: the chain above %q would never be created",
					parents[0], tc.remote)
			}
		})
	}
}

func TestRecursiveUploadOrderOfOperations(t *testing.T) {
	localDir := filepath.Join(t.TempDir(), "payload")
	if err := os.MkdirAll(filepath.Join(localDir, "sub"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, rel := range []string{"root.txt", filepath.Join("sub", "nested.txt")} {
		if err := os.WriteFile(filepath.Join(localDir, rel), []byte("data"), 0600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	t.Run("directories are created before anything is uploaded", func(t *testing.T) {
		srv := &recordingUploadServer{}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		withTestEndpoint(t, ts.URL)

		runRecursiveUpload(context.Background(), localDir, "/Backups")

		srv.mu.Lock()
		seq := append([]string(nil), srv.commands...)
		srv.mu.Unlock()

		lastMk, firstUl := -1, -1
		for i, c := range seq {
			if c == "mk" {
				lastMk = i
			}
			if c == "ul" && firstUl < 0 {
				firstUl = i
			}
		}
		if lastMk < 0 || firstUl < 0 {
			t.Fatalf("command sequence %v has no mk or no ul", seq)
		}
		if lastMk > firstUl {
			t.Errorf("sequence %v uploads into a directory that does not exist yet", seq)
		}
	})

	t.Run("skip-existing probes before transferring and skips a hit", func(t *testing.T) {
		srv := &recordingUploadServer{inExists: true}
		ts := httptest.NewServer(srv)
		defer ts.Close()
		withTestEndpoint(t, ts.URL)

		saved := ulSkipExisting
		ulSkipExisting = true
		defer func() { ulSkipExisting = saved }()

		runRecursiveUpload(context.Background(), localDir, "/Backups")

		srv.mu.Lock()
		defer srv.mu.Unlock()
		if len(srv.inPaths) != 2 {
			t.Errorf("probed %v, want one `in` per file", srv.inPaths)
		}
		if len(srv.ulPaths) != 0 {
			t.Errorf("transferred %v after the probe said the files are already there", srv.ulPaths)
		}
	})
}
