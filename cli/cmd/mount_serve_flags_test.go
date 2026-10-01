package cmd

import (
	"strings"
	"testing"

	"pigcloud/internal/mount/mlog"
)

func TestMountServeDeclaresEveryFlagTheParentSends(t *testing.T) {
	for _, name := range []string{"remote", "mountpoint", "cache-size", "poll", "mode", "read-only", "log-level"} {
		if mountServeCmd.Flags().Lookup(name) == nil {
			t.Errorf("__mount-serve does not declare --%s", name)
		}
	}
}

func TestMnStartExposesTheLogLevelKnob(t *testing.T) {
	f := mnStartCmd.Flags().Lookup("log-level")
	if f == nil {
		t.Fatal("mn start has no --log-level; the daemon verbosity is unreachable without editing the environment")
	}
	for _, lvl := range []string{"debug", "info", "warn", "error"} {
		if !strings.Contains(f.Usage, lvl) {
			t.Errorf("--log-level help does not mention %q: %q", lvl, f.Usage)
		}
		if _, ok := mlog.ParseLevel(lvl); !ok {
			t.Errorf("mlog rejects the documented level %q", lvl)
		}
	}
}
