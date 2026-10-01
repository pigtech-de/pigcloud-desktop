package mount

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/mount/mlog"
)

func TestMountLogPathKeyedLikeRegistryEntry(t *testing.T) {
	owner, remote := "ownerfp", "/Photos"

	p := MountLogPath(owner, remote)
	if !strings.HasSuffix(p, ".log") {
		t.Fatalf("log path %q lacks .log suffix", p)
	}
	if !strings.Contains(filepath.Base(p), mountKey(owner, remote)) {
		t.Fatalf("log path %q not keyed by mountKey", p)
	}
	if strings.TrimSuffix(entryFileName(owner, remote), ".json") != mountKey(owner, remote) {
		t.Fatalf("registry entry and log key diverged")
	}
	if MountLogPath("other", remote) == p || MountLogPath(owner, "/Docs") == p {
		t.Fatalf("log path collided across mounts")
	}
}

func TestRemoveFatalLogDropsTheSinkAndItsArchiveAndKeepsTheDaemonLog(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)

	owner, remote := "ownerfp", "/Photos"
	daemonLog := MountLogPath(owner, remote)
	fatal := mlog.FatalLogPath(daemonLog)
	other := mlog.FatalLogPath(MountLogPath(owner, "/Docs"))

	if err := os.MkdirAll(filepath.Dir(daemonLog), 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{daemonLog, fatal, fatal + ".1", other} {
		if err := os.WriteFile(path, []byte("trace\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}

	RemoveFatalLog(owner, remote)

	for _, gone := range []string{fatal, fatal + ".1"} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s survived the teardown; the mount's other leftovers go and this one "+
				"accumulates one file per crashed mount forever", filepath.Base(gone))
		}
	}
	if _, err := os.Stat(daemonLog); err != nil {
		t.Errorf("the daemon log went with the fatal sink: %v; it is the operational log a user "+
			"reads after a failed start, not a crash artifact", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("another mount's fatal sink was deleted: %v", err)
	}
}
