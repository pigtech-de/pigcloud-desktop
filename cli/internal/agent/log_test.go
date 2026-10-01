package agent

import (
	"bytes"
	"log"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const agentLogHelperEnv = "PIGCLOUD_AGENT_LOG_HELPER"

const helperTtl = 400 * time.Millisecond

func TestMain(m *testing.M) {
	if os.Getenv(agentLogHelperEnv) != "" {
		runAgentLogHelper()
		return
	}
	os.Exit(m.Run())
}

type failThenClose struct {
	net.Listener
	left int
}

func (l *failThenClose) Accept() (net.Conn, error) {
	if l.left > 0 {
		l.left--
		return nil, transientAcceptErr()
	}
	return nil, net.ErrClosed
}

func runAgentLogHelper() {
	defer startLogging()()

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	keys := &KeyMaterial{
		KyberPublicKey: make([]byte, 1184),
		KyberSeed:      make([]byte, 64),
		NameKey:        make([]byte, 32),
	}
	if os.Getenv(agentLogHelperEnv) == "ttl" {
		_, _, _ = serveListener(base, keys, helperTtl)
		return
	}
	_, _, _ = serveListener(&failThenClose{Listener: base, left: 1}, keys, 5*time.Second)
}

func TestSpawnedAgentLogLineIsRetrievableFromTheLogFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("detached spawn does not inherit the parent's handles the same way")
	}
	dir := isolateAgentDir(t)
	t.Setenv(agentLogHelperEnv, "1")

	if err := spawnWithExecutable(os.Args[0], spawnFixture(), 5); err != nil {
		t.Fatalf("spawn stand-in agent: %v", err)
	}

	logPath := filepath.Join(dir, "pigcloud", "agent.log")
	body := waitForLogLine(t, logPath, "accept failed")

	if !strings.Contains(body, "agent: accept failed, retrying in") {
		t.Errorf("agent log = %q, want the production accept-retry line", body)
	}
}

func TestSpawnedAgentLogIsNotWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits")
	}
	dir := isolateAgentDir(t)
	t.Setenv(agentLogHelperEnv, "1")

	if err := spawnWithExecutable(os.Args[0], spawnFixture(), 5); err != nil {
		t.Fatalf("spawn stand-in agent: %v", err)
	}

	logPath := filepath.Join(dir, "pigcloud", "agent.log")
	waitForLogLine(t, logPath, "accept failed")

	fi, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("stat agent log: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("agent log mode %04o, want 0600; it lives beside the 0600 agent.json", perm)
	}
}

func TestSpawnedAgentLogCarriesNoKeyMaterial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("detached spawn does not inherit the parent's handles the same way")
	}
	dir := isolateAgentDir(t)
	t.Setenv(agentLogHelperEnv, "1")

	if err := spawnWithExecutable(os.Args[0], spawnFixture(), 5); err != nil {
		t.Fatalf("spawn stand-in agent: %v", err)
	}

	logPath := filepath.Join(dir, "pigcloud", "agent.log")
	body := waitForWipeLine(t, logPath)
	fatal, _ := os.ReadFile(filepath.Join(dir, "pigcloud", "agent.fatal.log"))
	body += string(fatal)

	for label, secret := range spawnSecrets() {
		if strings.Contains(body, secret) {
			t.Errorf("agent log carries the %s", label)
		}
	}
	if !strings.Contains(body, "accept failed") {
		t.Error("accept-retry line missing; this grep no longer covers it")
	}
}

func TestSpawnedAgentLogsTheKeyWipeOnTtlExpiry(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("detached spawn does not inherit the parent's handles the same way")
	}
	dir := isolateAgentDir(t)
	t.Setenv(agentLogHelperEnv, "ttl")

	if err := spawnWithExecutable(os.Args[0], spawnFixture(), 5); err != nil {
		t.Fatalf("spawn stand-in agent: %v", err)
	}

	logPath := filepath.Join(dir, "pigcloud", "agent.log")
	body := waitForWipeLine(t, logPath)

	if !strings.Contains(body, helperTtl.String()) {
		t.Errorf("agent log = %q, want the elapsed TTL %s; without it the user cannot tell whether "+
			"to raise --ttl or hunt for a crash", body, helperTtl)
	}
}

func waitForWipeLine(t *testing.T, path string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(path); err == nil {
			last = string(b)
			if strings.Contains(last, wipeLogPrefix) {
				return last
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("agent log %s holds no %q line after the TTL expired; got %q. The agent zeroes the "+
		"hybrid private keys, the name key and both signing keypairs and exits without recording "+
		"it, so the log goes silent at exactly the moment every later command starts re-prompting "+
		"for the passphrase", path, wipeLogPrefix, last)
	return ""
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureAgentLog(t *testing.T) *syncBuffer {
	t.Helper()
	buf := &syncBuffer{}
	prev := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

func waitForLoggedText(t *testing.T, buf *syncBuffer, want, whenMissing string) string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := buf.String(); strings.Contains(got, want) {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}

	t.Fatalf("agent logged %q, want a line containing %q. %s", buf.String(), want, whenMissing)
	return ""
}

func TestTtlExpiryLogsTheWipeWithTheElapsedTtl(t *testing.T) {
	isolateAgentDir(t)
	buf := captureAgentLog(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	ttl := 300 * time.Millisecond
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = serveListener(ln, testKeys(t), ttl)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent goroutine outlived the test; listener leaked")
		}
	})

	got := waitForLoggedText(t, buf, wipeLogPrefix,
		"the TTL fired, the keys are gone, and nothing recorded it")
	if !strings.Contains(got, ttl.String()) {
		t.Errorf("wipe line = %q, want the elapsed TTL %s so a scheduled expiry reads as one",
			strings.TrimSpace(got), ttl)
	}
}

func TestExplicitShutdownLogsItsOwnReason(t *testing.T) {
	isolateAgentDir(t)
	buf := captureAgentLog(t)

	serveInBackground(t, testKeys(t), 30*time.Second)
	waitForAgent(t)

	if err := Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}

	got := waitForLoggedText(t, buf, wipeLogPrefix, "a lock request wipes the keys unrecorded")
	if strings.Contains(got, "ttl") {
		t.Errorf("wipe line = %q; a lock request logged as a TTL expiry sends the reader after "+
			"the wrong cause, which is the whole point of the reason", strings.TrimSpace(got))
	}
}

func TestListenerCloseLogsItsOwnReason(t *testing.T) {
	isolateAgentDir(t)
	buf := captureAgentLog(t)

	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("bind loopback listener: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = serveListener(&failThenClose{Listener: base}, testKeys(t), 30*time.Second)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent goroutine outlived the test; listener leaked")
		}
	})

	got := waitForLoggedText(t, buf, wipeLogPrefix, "a dead listener wipes the keys unrecorded")
	if strings.Contains(got, "ttl") {
		t.Errorf("wipe line = %q; a closed listener is not a TTL expiry and must not read as one",
			strings.TrimSpace(got))
	}
}

func TestAgentLogPathSitsBesideTheAgentFile(t *testing.T) {
	dir := isolateAgentDir(t)

	p := agentLogPath()
	if want := filepath.Join(dir, "pigcloud", "agent.log"); p != want {
		t.Fatalf("agent log path %q, want %q", p, want)
	}
	if filepath.Dir(p) != filepath.Dir(agentFilePath()) {
		t.Error("agent log left the config dir that holds agent.json")
	}
	if strings.HasPrefix(filepath.Base(p), "mount-") {
		t.Errorf("agent log %q collides with the per-mount log namespace", filepath.Base(p))
	}
}

func TestOpenAgentLogAppendsBelowCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")

	lf, err := openAgentLog(path)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	lf.WriteString("first\n")
	lf.Close()

	lf, err = openAgentLog(path)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	lf.WriteString("second\n")
	lf.Close()

	data, _ := os.ReadFile(path)
	if got := string(data); got != "first\nsecond\n" {
		t.Fatalf("respawn truncated the prior agent's trace: %q", got)
	}
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatal("rotated below cap, .1 should not exist")
	}
}

func TestOpenAgentLogRotatesOverCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")

	big := strings.Repeat("x", maxAgentLogSize+1)
	if err := os.WriteFile(path, []byte(big), 0600); err != nil {
		t.Fatal(err)
	}

	lf, err := openAgentLog(path)
	if err != nil {
		t.Fatalf("open over cap: %v", err)
	}
	lf.WriteString("fresh\n")
	lf.Close()

	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("prior log not rotated to .1: %v", err)
	}
	if len(rotated) != len(big) {
		t.Fatalf(".1 size = %d, want %d", len(rotated), len(big))
	}
	if data, _ := os.ReadFile(path); string(data) != "fresh\n" {
		t.Fatalf("post-rotation log = %q, want a fresh start", data)
	}
}

func TestAgentLogStaysCappedWithinOneTtl(t *testing.T) {
	dir := isolateAgentDir(t)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _, _ = Serve(testKeys(t), 30*time.Second)
	}()
	waitForAgent(t)
	t.Cleanup(func() {
		_ = Shutdown()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("agent goroutine outlived the test; listener leaked")
		}
	})

	line := strings.Repeat("x", 4096)
	for written := 0; written < maxAgentLogSize+(1<<16); written += len(line) {
		log.Printf("agent: accept failed, retrying in 5ms: %s", line)
	}

	path := filepath.Join(dir, "pigcloud", "agent.log")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat agent log: %v", err)
	}
	if fi.Size() > maxAgentLogSize {
		t.Errorf("agent log grew to %d bytes, past the %d cap. The agent rotates at spawn only, so a "+
			"TTL of accept-retry lines fills the disk beside the bearer token with nothing to stop it",
			fi.Size(), maxAgentLogSize)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("no rotated .1 beside the capped log: %v; the lines over the cap were dropped rather "+
			"than archived, so the trace of what filled it is gone", err)
	}
}

func waitForLogLine(t *testing.T, path, want string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		b, err := os.ReadFile(path)
		if err == nil {
			last = string(b)
			if strings.Contains(last, want) {
				return last
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("agent log %s was never created; the spawned agent's fd 2 still goes nowhere, "+
			"so nothing it logs mid-TTL is recoverable", path)
	}
	t.Fatalf("agent log never contained %q; got %q", want, last)
	return ""
}
