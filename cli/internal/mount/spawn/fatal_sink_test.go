package spawn

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"pigcloud/internal/crypto"
	"pigcloud/internal/mount"
	"pigcloud/internal/mount/mlog"
)

const fatalHelperEnv = "PIGCLOUD_MOUNT_FATAL_HELPER"

func TestMain(m *testing.M) {
	switch os.Getenv(fatalHelperEnv) {
	case "":
		os.Exit(m.Run())
	case "keys":
		raw, _ := io.ReadAll(os.Stdin)
		var keys Keys
		_ = json.Unmarshal(raw, &keys)
		defer runtime.KeepAlive(keys)
		panic("mount daemon helper: unrecovered runtime fatal")
	default:
		io.Copy(io.Discard, os.Stdin)
		panic("mount daemon helper: unrecovered runtime fatal")
	}
}

func isolateConfigDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	if got := mount.ConfigDir(); !strings.HasPrefix(got, dir) {
		t.Fatalf("config dir %q escaped the temp dir %q", got, dir)
	}
}

func waitForTrace(t *testing.T, path string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if body, err := os.ReadFile(path); err == nil && strings.Contains(string(body), "panic:") {
			return string(body)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ""
}

func TestSpawnedDaemonFatalLandsInTheNonRotatingSink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("detached spawn does not inherit the parent's handles the same way")
	}
	isolateConfigDir(t)
	if err := os.MkdirAll(mount.ConfigDir(), 0700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	t.Setenv(fatalHelperEnv, "1")

	pub := make([]byte, 32)
	pub[0] = 0xA5
	keys := Keys{PubHex: hex.EncodeToString(pub)}
	remote := "/Photos"

	err := backgroundWithExecutable(os.Args[0], remote, t.TempDir(), keys,
		1<<30, 30, mount.ModeSync, false, "info")
	if err != nil {
		t.Fatalf("spawn stand-in daemon: %v", err)
	}

	fingerprint := crypto.AccountFingerprint(pub)
	sink := FatalSinkPath(fingerprint, remote)
	daemonLog := mount.MountLogPath(fingerprint, remote)

	if sink == daemonLog {
		t.Fatal("the sink and the rotating daemon log are the same file")
	}

	trace := waitForTrace(t, sink)
	if trace == "" {
		t.Errorf("no panic trace at %s after 10s; the child's fd 2 is not pointed at the non-rotating sink", sink)
	}

	if body, rerr := os.ReadFile(daemonLog); rerr == nil && strings.Contains(string(body), "panic:") {
		t.Errorf("the trace landed in the rotating daemon log %s; a mid-run rotation would carry it into the archive and then nowhere", daemonLog)
	}
}

func mountSpawnSecrets() map[string]string {
	return map[string]string{
		"x25519 private key":          strings.Repeat("a1", 32),
		"ml-kem seed":                 strings.Repeat("b2", 64),
		"name key":                    strings.Repeat("c3", 32),
		"ed25519 signing private key": strings.Repeat("d4", 64),
		"ml-dsa signing private key":  strings.Repeat("e5", 2560),
	}
}

func mountSpawnFixture(pub []byte) Keys {
	s := mountSpawnSecrets()
	return Keys{
		PubHex:        hex.EncodeToString(pub),
		PrivHex:       s["x25519 private key"],
		KyberPubHex:   strings.Repeat("22", 1184),
		KyberSeedHex:  s["ml-kem seed"],
		NameKeyHex:    s["name key"],
		SignPubEdHex:  strings.Repeat("33", 32),
		SignPrivEdHex: s["ed25519 signing private key"],
		SignPubMlHex:  strings.Repeat("44", 1312),
		SignPrivMlHex: s["ml-dsa signing private key"],
	}
}

func TestSpawnedDaemonFatalLogCarriesNoKeyMaterial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("detached spawn does not inherit the parent's handles the same way")
	}
	isolateConfigDir(t)
	if err := os.MkdirAll(mount.ConfigDir(), 0700); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	t.Setenv(fatalHelperEnv, "keys")

	pub := make([]byte, 32)
	pub[0] = 0xA5
	remote := "/Photos"
	keys := mountSpawnFixture(pub)

	payload, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("marshal spawn keys: %v", err)
	}
	for label, secret := range mountSpawnSecrets() {
		if !strings.Contains(string(payload), secret) {
			t.Fatalf("the %s never reaches the child, so the search below proves nothing", label)
		}
	}

	if err := backgroundWithExecutable(os.Args[0], remote, t.TempDir(), keys,
		1<<30, 30, mount.ModeSync, false, "info"); err != nil {
		t.Fatalf("spawn stand-in daemon: %v", err)
	}

	sink := FatalSinkPath(crypto.AccountFingerprint(pub), remote)
	trace := waitForTrace(t, sink)
	if trace == "" {
		t.Fatalf("no panic trace at %s after 10s; nothing was searched for key material", sink)
	}

	for label, secret := range mountSpawnSecrets() {
		if strings.Contains(trace, secret) {
			t.Errorf("the mount fatal log carries the %s, and printMountLogHint echoes this file to stderr on the next `pc mn` failure", label)
		}
	}
}

func TestFatalSinkPathIsASiblingOfTheDaemonLog(t *testing.T) {
	isolateConfigDir(t)

	sink := FatalSinkPath("ownerfp", "/Photos")
	daemonLog := mount.MountLogPath("ownerfp", "/Photos")

	if sink == daemonLog {
		t.Fatal("the sink must not be the file the daemon rotates")
	}
	if filepath.Dir(sink) != filepath.Dir(daemonLog) {
		t.Errorf("sink %q left the config dir", sink)
	}
	if sink != mlog.FatalLogPath(daemonLog) {
		t.Errorf("sink %q disagrees with mlog.FatalLogPath(%q)", sink, daemonLog)
	}
	if FatalSinkPath("other", "/Photos") == sink || FatalSinkPath("ownerfp", "/Docs") == sink {
		t.Error("sink collided across mounts")
	}
}

func TestFatalSinkIsEmptyForAnUndecodablePublicKey(t *testing.T) {
	if got := fatalSinkFor(Keys{PubHex: "not-hex"}, "/Photos"); got != "" {
		t.Errorf("fatalSinkFor = %q, want empty so the spawn falls back to discard", got)
	}
}
