package mlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAHandleOnTheFatalPathSurvivesADaemonLogRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "mount-abc.log")

	fd2, err := OpenLog(FatalLogPath(logPath))
	if err != nil {
		t.Fatalf("open fatal sink: %v", err)
	}
	defer fd2.Close()

	daemonLog, err := NewRotatingLog(logPath)
	if err != nil {
		t.Fatalf("NewRotatingLog: %v", err)
	}
	defer daemonLog.Close()
	if _, err := daemonLog.Write([]byte(strings.Repeat("x", MaxLogSize) + "\n")); err != nil {
		t.Fatalf("fill the daemon log: %v", err)
	}
	if _, err := daemonLog.Write([]byte("post-rotation line\n")); err != nil {
		t.Fatalf("write past the cap: %v", err)
	}
	if _, err := os.Stat(logPath + ".1"); err != nil {
		t.Fatalf("fixture guard: the daemon log did not rotate, so nothing is being tested: %v", err)
	}

	if _, err := fd2.WriteString("panic: runtime error\n"); err != nil {
		t.Fatalf("write the panic trace: %v", err)
	}

	landed, err := os.ReadFile(FatalLogPath(logPath))
	if err != nil {
		t.Fatalf("read the fatal sink: %v", err)
	}
	if !strings.Contains(string(landed), "panic: runtime error") {
		t.Errorf("the panic trace did not land at %s; the child's fd 2 is writing to an inode the rotation moved away",
			FatalLogPath(logPath))
	}
}

func TestFatalLogPathIsASiblingOfTheDaemonLog(t *testing.T) {
	logPath := filepath.Join("cfg", "mount-abc.log")
	fatal := FatalLogPath(logPath)

	if fatal == logPath {
		t.Fatal("the fatal sink must not be the file the daemon rotates")
	}
	if filepath.Dir(fatal) != filepath.Dir(logPath) {
		t.Errorf("fatal sink %q left the config dir", fatal)
	}
	if !strings.HasPrefix(filepath.Base(fatal), "mount-abc") {
		t.Errorf("fatal sink %q is not keyed to its mount", fatal)
	}
	if strings.HasSuffix(fatal, ".log.1") {
		t.Errorf("fatal sink %q collides with the rotation archive", fatal)
	}
}
