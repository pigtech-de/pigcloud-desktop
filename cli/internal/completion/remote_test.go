package completion

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/filetypes"
)

func knownExt(t *testing.T) (string, string) {
	t.Helper()
	exts := filetypes.Extensions()
	if len(exts) == 0 {
		t.Fatal("registry exposed no extensions")
	}
	sort.Strings(exts)
	known := ""
	for _, e := range exts {
		if filetypes.TypeOf(e) != "other" {
			known = e
			break
		}
	}
	if known == "" {
		t.Fatal("no categorized extension in the registry")
	}
	unknown := "qqqqqqq"
	if filetypes.TypeOf(unknown) != "other" {
		t.Fatal("pick a new unknown extension for this guard")
	}
	return known, unknown
}

type lsServer struct {
	mu       sync.Mutex
	byDir    map[string][]api.ListEntry
	requests []string
}

func newCompletionEnv(t *testing.T) *lsServer {
	t.Helper()
	s := &lsServer{byDir: map[string][]api.ListEntry{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Command string            `json:"command"`
			Options map[string]string `json:"options"`
		}
		json.Unmarshal(body, &req)
		s.mu.Lock()
		s.requests = append(s.requests, req.Options["source"])
		entries := s.byDir[req.Options["source"]]
		s.mu.Unlock()
		raw, _ := json.Marshal(map[string]any{"success": true, "entries": entries})
		w.Header().Set("Content-Type", "application/json")
		w.Write(raw)
	}))
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	origCfg := config.GetConfigPath()
	config.SetConfigFile(filepath.Join(dir, "pigcloud", "config.json"))
	config.Load()
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "completion-test"
	t.Cleanup(func() {
		config.SetConfigFile(origCfg)
		config.Load()
	})

	cache = map[string]cacheEntry{}
	t.Cleanup(func() { cache = map[string]cacheEntry{} })
	return s
}

func (s *lsServer) set(dir string, entries []api.ListEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byDir[dir] = entries
}

func (s *lsServer) requestCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.requests)
}

func complete(toComplete string) ([]string, cobra.ShellCompDirective) {
	return RemotePathCompletion(&cobra.Command{}, nil, toComplete)
}

func TestRemotePathCompletionRequiresLogin(t *testing.T) {
	newCompletionEnv(t)
	config.Get().APIKey = ""
	got, directive := complete("")
	if got != nil || directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("logged-out completion: %v %v", got, directive)
	}
}

func TestRemotePathCompletionCategorizesByRegistry(t *testing.T) {
	srv := newCompletionEnv(t)
	known, unknown := knownExt(t)
	srv.set("/", []api.ListEntry{
		{Name: "Docs", Type: "directory"},
		{Name: "pic." + known, Type: "file"},
		{Name: "blob." + unknown, Type: "file"},
		{Name: "", Type: "file"},
		{Name: "(encrypted)", Type: "file"},
	})

	got, directive := complete("")
	if directive&cobra.ShellCompDirectiveNoSpace == 0 || directive&cobra.ShellCompDirectiveNoFileComp == 0 {
		t.Errorf("directive = %v", directive)
	}
	want := map[string]bool{
		"Docs/\tdir": true,
		"pic." + known + "\t" + filetypes.TypeOf(known): true,
		"blob." + unknown: true,
	}
	if len(got) != len(want) {
		t.Fatalf("completions = %v, want keys %v", got, want)
	}
	for _, c := range got {
		if !want[c] {
			t.Errorf("unexpected completion %q", c)
		}
	}
}

func TestRemotePathCompletionPrefixFilterIsCaseInsensitive(t *testing.T) {
	srv := newCompletionEnv(t)
	srv.set("/", []api.ListEntry{
		{Name: "Docs", Type: "directory"},
		{Name: "Downloads", Type: "directory"},
		{Name: "Pictures", Type: "directory"},
	})

	got, _ := complete("do")
	if len(got) != 2 {
		t.Fatalf("prefix filter: %v", got)
	}
	for _, c := range got {
		if !strings.HasPrefix(strings.ToLower(c), "do") {
			t.Errorf("non-matching completion %q", c)
		}
	}
	if got2, _ := complete("zz"); len(got2) != 0 {
		t.Errorf("unmatched prefix returned %v", got2)
	}
}

func TestRemotePathCompletionAbsoluteAndSubdirPaths(t *testing.T) {
	srv := newCompletionEnv(t)
	srv.set("/", []api.ListEntry{{Name: "Docs", Type: "directory"}})
	srv.set("/Docs", []api.ListEntry{{Name: "inner.txt", Type: "file"}})

	got, _ := complete("/Do")
	if len(got) != 1 || !strings.HasPrefix(got[0], "/Docs/") {
		t.Errorf("absolute completion: %v", got)
	}

	got, _ = complete("Docs/")
	if len(got) != 1 || !strings.HasPrefix(got[0], "Docs/inner.txt") {
		t.Errorf("subdir completion: %v", got)
	}

	got, _ = complete("Docs/in")
	if len(got) != 1 || !strings.HasPrefix(got[0], "Docs/inner.txt") {
		t.Errorf("subdir prefix completion: %v", got)
	}
}

func TestRemotePathCompletionCachesListings(t *testing.T) {
	srv := newCompletionEnv(t)
	srv.set("/", []api.ListEntry{{Name: "Docs", Type: "directory"}})

	complete("")
	complete("D")
	complete("Do")
	if n := srv.requestCount(); n != 1 {
		t.Errorf("ls requests = %d, want 1 (cache must absorb repeat tab presses)", n)
	}
}

func TestRemotePathCompletionServerFailure(t *testing.T) {
	newCompletionEnv(t)
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"success":false,"message":"nope"}`)
	}))
	t.Cleanup(fail.Close)
	config.Get().Endpoint = fail.URL

	got, directive := complete("")
	if got != nil || directive != cobra.ShellCompDirectiveNoFileComp {
		t.Errorf("failure path: %v %v", got, directive)
	}
}
