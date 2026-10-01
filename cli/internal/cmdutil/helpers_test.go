package cmdutil

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/output"

	"golang.org/x/term"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "pigcloud-cmdutil-test-*")
	if err == nil {
		config.SetConfigFile(filepath.Join(dir, "config.json"))
		config.Load()
	}
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

func fakeEndpoint(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "helpers-test"
	return srv
}

func isolateKeyEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)

	origCfg := config.GetConfigPath()
	config.SetConfigFile(filepath.Join(dir, "pigcloud", "config.json"))
	config.Load()

	origStdin := os.Stdin
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	os.Stdin = devnull

	t.Cleanup(func() {
		os.Stdin = origStdin
		devnull.Close()
		config.SetConfigFile(origCfg)
		config.Load()
	})
}

func requireNonInteractiveStdin(t *testing.T) {
	t.Helper()
	if term.IsTerminal(int(syscall.Stdin)) {
		t.Skip("fd 0 is a terminal; the password prompt would block")
	}
}

func jsonHandler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	}
}

func TestResolvePath(t *testing.T) {

	tests := []struct {
		input string
		want  string
	}{
		{"", "/"},
		{"/", "/"},
		{"/docs", "/docs"},
		{"/docs/../photos", "/photos"},
	}

	for _, tt := range tests {
		got := ResolvePath(tt.input)
		if got != tt.want {
			t.Errorf("ResolvePath(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestStripMSYSConversion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", ""},
		{"/", "/"},
		{"/documents", "/documents"},
		{"relative/path", "relative/path"},
	}
	for _, tt := range tests {
		got := stripMSYSConversion(tt.input)
		if got != tt.want {
			t.Errorf("stripMSYSConversion(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRequireLogin(t *testing.T) {
	isolateKeyEnv(t)

	exited := false
	RequireLogin(func() { exited = true })
	if !exited {
		t.Error("missing API key did not exit")
	}

	config.Get().APIKey = "some-key"
	exited = false
	RequireLogin(func() { exited = true })
	if exited {
		t.Error("logged-in user was exited")
	}
}

func TestResolvePathAgainstCwd(t *testing.T) {
	isolateKeyEnv(t)
	config.Get().Cwd = "/docs/reports"

	cases := []struct {
		in   string
		want string
	}{
		{"", "/docs/reports"},
		{"q3.pdf", "/docs/reports/q3.pdf"},
		{"../top.txt", "/docs/top.txt"},
		{"./x", "/docs/reports/x"},
		{"/abs/./y/../z", "/abs/z"},
		{"/", "/"},
	}
	for _, c := range cases {
		if got := ResolvePath(c.in); got != c.want {
			t.Errorf("ResolvePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestPrintJSONOrContinue(t *testing.T) {
	if PrintJSONOrContinue(false, map[string]int{"a": 1}) {
		t.Error("json disabled must return false")
	}
	if !PrintJSONOrContinue(true, map[string]int{"a": 1}) {
		t.Error("json enabled must return true")
	}
	if !PrintJSONOrContinue(true, make(chan int)) {
		t.Error("marshal failure must still return true")
	}
}

func TestConfirmAction(t *testing.T) {
	requireNonInteractiveStdin(t)
	if !ConfirmAction("really?", true) {
		t.Error("force must skip the prompt")
	}
	if !ConfirmAction("really?", false) {
		t.Error("non-tty stdin must not block on a prompt")
	}
}

func TestExecuteCommandDecodesPayload(t *testing.T) {
	isolateKeyEnv(t)
	fakeEndpoint(t, jsonHandler(`{"success":true,"path":"/x","entries":[{"name":"a","path":"/x/a","type":"file"}]}`))

	exited := false
	resp, payload := ExecuteCommand[api.ListPayload](context.Background(), "ls", map[string]string{"source": "/x"}, func() { exited = true })
	if exited {
		t.Fatal("successful command exited")
	}
	if resp == nil || !resp.Success {
		t.Fatalf("resp: %+v", resp)
	}
	if payload.Path != "/x" || len(payload.Entries) != 1 || payload.Entries[0].Name != "a" {
		t.Errorf("payload: %+v", payload)
	}
}

func TestExecuteCommandExitsOnServerRejection(t *testing.T) {
	isolateKeyEnv(t)
	fakeEndpoint(t, jsonHandler(`{"success":false,"message":"denied"}`))

	exited := false
	resp, _ := ExecuteCommand[api.ListPayload](context.Background(), "ls", nil, func() { exited = true })
	if !exited || resp != nil {
		t.Errorf("rejection: exited=%v resp=%v", exited, resp)
	}
}

func TestExecuteCommandExitsOnMalformedPayload(t *testing.T) {
	isolateKeyEnv(t)
	fakeEndpoint(t, jsonHandler(`{"success":true,"details":"not-an-object"}`))

	exited := false
	ExecuteCommand[api.InfoPayload](context.Background(), "in", nil, func() { exited = true })
	if !exited {
		t.Error("payload type mismatch did not exit")
	}
}

func TestIsExistingDirectory(t *testing.T) {
	isolateKeyEnv(t)

	if !IsExistingDirectory(context.Background(), "/") {
		t.Error("root must always be a directory")
	}
	if !IsExistingDirectory(context.Background(), "") {
		t.Error("empty path must count as root")
	}

	var mu sync.Mutex
	kind := "directory"
	fakeEndpoint(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		k := kind
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"details":{"type":%q}}`, k)
	})

	if !IsExistingDirectory(context.Background(), "/Docs") {
		t.Error("directory probe returned false")
	}
	mu.Lock()
	kind = "file"
	mu.Unlock()
	if IsExistingDirectory(context.Background(), "/Docs/a.txt") {
		t.Error("file reported as directory")
	}

	fakeEndpoint(t, jsonHandler(`{"success":false,"message":"gone"}`))
	if IsExistingDirectory(context.Background(), "/missing") {
		t.Error("server rejection reported as directory")
	}
}

func TestRenderServerDisplay(t *testing.T) {
	isolateKeyEnv(t)

	if RenderServerDisplay(nil) {
		t.Error("nil response rendered")
	}
	if RenderServerDisplay(&api.Response{}) {
		t.Error("empty raw rendered")
	}
	if RenderServerDisplay(&api.Response{Raw: json.RawMessage(`{"success":true}`)}) {
		t.Error("response without _display rendered")
	}
	if RenderServerDisplay(&api.Response{Raw: json.RawMessage(`{"_display":[]}`)}) {
		t.Error("empty block list rendered")
	}
	if RenderServerDisplay(&api.Response{Raw: json.RawMessage(`{"_display":"nope"}`)}) {
		t.Error("malformed _display rendered")
	}

	plain := &api.Response{Raw: json.RawMessage(`{"_display":[{"type":"text","text":"hello"}]}`)}
	if !RenderServerDisplay(plain) {
		t.Error("text block not rendered")
	}

	blocks := []output.DisplayBlock{{
		Type: "table",
		Rows: [][]output.DisplayCell{{{Name: "c2VhbGVk", FileType: "file"}}},
	}}
	rawBlocks, _ := json.Marshal(map[string]any{"_display": blocks})
	if !RenderServerDisplay(&api.Response{Raw: rawBlocks}) {
		t.Error("locked-keys path must still consume the display")
	}
}
