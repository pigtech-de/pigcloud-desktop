package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/mount"
)

func writeLog(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mount-test.log")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("write fixture log: %v", err)
	}
	return path
}

func TestTailLinesReturnsTheLastLines(t *testing.T) {
	path := writeLog(t, "first\nsecond\nthird\nfourth\n")

	got := tailLines(path, 2)
	want := []string{"third", "fourth"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("tailLines = %v, want %v", got, want)
	}
}

func TestTailLinesSkipsBlanksAndKeepsPanicTraces(t *testing.T) {
	path := writeLog(t, "starting\n\npanic: runtime error: index out of range\n\ngoroutine 1 [running]:\n")

	got := tailLines(path, mountLogTailLines)
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "panic: runtime error") {
		t.Errorf("panic line must survive the tail, got %v", got)
	}
	for _, l := range got {
		if strings.TrimSpace(l) == "" {
			t.Errorf("blank line leaked into the tail: %v", got)
		}
	}
}

func TestTailLinesReadsOnlyTheEndOfALargeLog(t *testing.T) {
	var b strings.Builder
	for i := range 4000 {
		fmt.Fprintf(&b, "line %04d %s\n", i, strings.Repeat("x", 64))
	}
	path := writeLog(t, b.String())

	got := tailLines(path, 3)
	if len(got) != 3 {
		t.Fatalf("tailLines returned %d lines, want 3", len(got))
	}
	if !strings.HasPrefix(got[2], "line 3999 ") {
		t.Errorf("last line = %q, want the final log line", got[2])
	}

	all := tailLines(path, 5000)
	if len(all) < 2 {
		t.Fatalf("tailLines returned %d lines from an 8 KiB window; the partial-line check needs the whole window", len(all))
	}
	if len(all) > 500 {
		t.Errorf("tailLines returned %d lines; it slurped the file instead of reading the tail", len(all))
	}
	for i, l := range all {
		if !strings.HasPrefix(l, "line ") {
			t.Errorf("partial line leaked from the offset read at index %d: %q", i, l)
		}
	}
}

func TestTailLinesToleratesAMissingLog(t *testing.T) {
	if got := tailLines(filepath.Join(t.TempDir(), "absent.log"), 5); got != nil {
		t.Errorf("missing log should tail to nil, got %v", got)
	}
}

func TestMountLogPathIsReachableAndKeyed(t *testing.T) {
	p := mount.MountLogPath("abcd1234", "/Photos")
	if p == "" {
		t.Fatal("MountLogPath returned an empty path")
	}
	if p == mount.MountLogPath("abcd1234", "/Docs") {
		t.Error("two remote paths share one log file")
	}
	if p == mount.MountLogPath("beef5678", "/Photos") {
		t.Error("two accounts share one log file")
	}
}
