package agent

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func isolateAgentDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	t.Cleanup(RemoveAgentFile)

	if got, want := agentFilePath(), filepath.Join(dir, "pigcloud", "agent.json"); got != want {
		t.Fatalf("agent file path %q escaped the temp dir (want %q)", got, want)
	}
	return dir
}

func TestWriteAgentFileIsReadableOnlyByTheOwner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	isolateAgentDir(t)

	info := &AgentInfo{
		Port:    45678,
		Token:   fixtureToken,
		PID:     os.Getpid(),
		Expires: time.Now().Add(time.Hour),
	}
	if err := writeAgentFile(info); err != nil {
		t.Fatalf("writeAgentFile: %v", err)
	}

	path := agentFilePath()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !bytes.Contains(data, []byte(info.Token)) {
		t.Fatalf("agent file holds no token; the mode assertions below would prove nothing")
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("agent.json mode %04o, want 0600: the file carries the agent bearer token", perm)
	}

	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := di.Mode().Perm(); perm != 0o700 {
		t.Errorf("config dir mode %04o, want 0700", perm)
	}
}

func TestWriteAgentFileFailsWhenTheConfigDirCannotExist(t *testing.T) {
	dir := isolateAgentDir(t)
	if err := os.WriteFile(filepath.Join(dir, "pigcloud"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocking file: %v", err)
	}

	if err := writeAgentFile(&AgentInfo{Port: 1, Token: fixtureToken}); err == nil {
		t.Error("writeAgentFile reported success with no writable config dir")
	}
	if got := ReadAgentFile(); got != nil {
		t.Errorf("ReadAgentFile returned info after a failed write: port=%d", got.Port)
	}
}

func TestServeFailsClosedWhenTheAgentFileCannotBeWritten(t *testing.T) {
	dir := isolateAgentDir(t)
	if err := os.WriteFile(filepath.Join(dir, "pigcloud"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocking file: %v", err)
	}

	port, token, err := Serve(testKeys(t), time.Minute)
	if err == nil {
		t.Fatal("Serve started an agent it could not advertise")
	}
	if port != 0 {
		t.Errorf("Serve returned port %d on its failure path, want 0", port)
	}
	if token != "" {
		t.Errorf("Serve returned a %d-character token on its failure path, want none", len(token))
	}
}

func TestReadAgentFileFailsClosedOnCorruptContent(t *testing.T) {
	isolateAgentDir(t)
	path := agentFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cases := []struct {
		name string
		body string
	}{
		{"empty file", ""},
		{"whitespace only", "   \n"},
		{"truncated json", `{"port":4711,"token":"abc`},
		{"not json", "this is not json"},
		{"json array", `[{"port":4711,"token":"abc"}]`},
		{"json string", `"nope"`},
		{"wrong field type", `{"port":"4711","token":"abc"}`},
		{"trailing garbage", `{"port":4711,"token":"abc"} and then some`},
		{"expired", `{"port":4711,"token":"abc","pid":1,"expires":"2000-01-01T00:00:00Z"}`},
		{"malformed expiry", `{"port":4711,"token":"abc","expires":"not-a-time"}`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			if got := ReadAgentFile(); got != nil {
				t.Fatalf("accepted %s: port=%d, token present=%v, expires=%v",
					tc.name, got.Port, got.Token != "", got.Expires)
			}
			if Ping() {
				t.Error("Ping succeeded off a corrupt agent file")
			}
			if RequestKeys() != nil {
				t.Error("RequestKeys returned material off a corrupt agent file")
			}
		})
	}
}

func TestReadAgentFileReturnsNilWhenAbsent(t *testing.T) {
	isolateAgentDir(t)

	if got := ReadAgentFile(); got != nil {
		t.Fatalf("ReadAgentFile invented info for a missing file: %+v", got)
	}
	if Ping() {
		t.Error("Ping succeeded with no agent file")
	}
	if IsRunning() {
		t.Error("IsRunning true with no agent file")
	}
	if RequestKeys() != nil {
		t.Error("RequestKeys returned material with no agent file")
	}
	if err := Shutdown(); err != nil {
		t.Errorf("Shutdown with no agent file: %v", err)
	}
}

func TestReadAgentFileDeletesAnExpiredFile(t *testing.T) {
	isolateAgentDir(t)

	info := &AgentInfo{Port: 4711, Token: fixtureToken, PID: os.Getpid(), Expires: time.Now().Add(-time.Second)}
	if err := writeAgentFile(info); err != nil {
		t.Fatalf("writeAgentFile: %v", err)
	}
	if got := ReadAgentFile(); got != nil {
		t.Fatalf("expired agent file was accepted: %+v", got)
	}
	if _, err := os.Stat(agentFilePath()); !os.IsNotExist(err) {
		t.Errorf("expired agent file survived the read (stat err %v); the stale token stays on disk", err)
	}
}

func TestAgentFileRoundTrip(t *testing.T) {
	isolateAgentDir(t)

	want := &AgentInfo{
		Port:    61234,
		Token:   fixtureToken,
		PID:     4242,
		Expires: time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second),
	}
	if err := writeAgentFile(want); err != nil {
		t.Fatalf("writeAgentFile: %v", err)
	}

	got := ReadAgentFile()
	if got == nil {
		t.Fatal("ReadAgentFile rejected a file it just wrote")
	}
	if got.Port != want.Port {
		t.Errorf("port = %d, want %d", got.Port, want.Port)
	}
	if got.Token != want.Token {
		t.Errorf("token did not survive the round trip")
	}
	if got.PID != want.PID {
		t.Errorf("pid = %d, want %d", got.PID, want.PID)
	}
	if !got.Expires.Equal(want.Expires) {
		t.Errorf("expires = %v, want %v", got.Expires, want.Expires)
	}

	RemoveAgentFile()
	if ReadAgentFile() != nil {
		t.Error("RemoveAgentFile left a readable agent file")
	}
}

func TestTokenlessAgentFileYieldsNoKeys(t *testing.T) {
	isolateAgentDir(t)
	path := agentFilePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	for _, body := range []string{`{}`, `null`} {
		write := func() {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
		}

		write()
		if got := RequestKeys(); got != nil {
			t.Errorf("RequestKeys returned material for agent file %s", body)
		}
		write()
		if Ping() {
			t.Errorf("Ping succeeded against agent file %s", body)
		}
		write()
		if IsRunning() {
			t.Errorf("IsRunning true for agent file %s", body)
		}
	}
}
