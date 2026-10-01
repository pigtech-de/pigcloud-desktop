package mlog

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenLogHandlesAlwaysAppendWithoutOverwritingEachOther(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")
	first, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, write := range []struct {
		file *os.File
		text string
	}{{first, "first\n"}, {second, "second\n"}, {first, "third\n"}} {
		if _, err := write.file.WriteString(write.text); err != nil {
			t.Fatal(err)
		}
	}
	actual, err := os.ReadFile(path)
	if err != nil || string(actual) != "first\nsecond\nthird\n" {
		t.Fatalf("append handles overwrote prior log bytes: %q, %v", actual, err)
	}
}

func TestFailedRotationRetainsSizeAndRetriesWithoutLosingBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mount.log")
	file, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	log := Rotating(path, file, 4)
	t.Cleanup(func() { log.Close() })
	log.rename = func(string) error { return os.ErrPermission }
	if _, err := log.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Write([]byte("56")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if log.size != info.Size() || log.size != 6 {
		t.Fatalf("failed rename hid the existing log size: tracked=%d actual=%d", log.size, info.Size())
	}
	log.rename = nil
	if _, err := log.Write([]byte("7")); err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(path + ".1")
	if err != nil || string(archive) != "123456" {
		t.Fatalf("rotation did not retry with intact prior bytes: %q %v", archive, err)
	}
	live, err := os.ReadFile(path)
	if err != nil || string(live) != "7" {
		t.Fatalf("new log was not appended after recovery: %q %v", live, err)
	}
}
