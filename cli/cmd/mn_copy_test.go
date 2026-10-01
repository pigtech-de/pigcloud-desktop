package cmd

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func buildRandomTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	want := map[string][]byte{}
	dirs := []string{""}

	for i := 0; i < 3+randInt(t, 6); i++ {
		parent := dirs[randInt(t, len(dirs))]
		rel := filepath.Join(parent, "d"+string(rune('a'+randInt(t, 6))))
		if err := os.MkdirAll(filepath.Join(root, rel), 0700); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		dirs = append(dirs, rel)
	}
	for i := 0; i < 5+randInt(t, 12); i++ {
		parent := dirs[randInt(t, len(dirs))]
		rel := filepath.Join(parent, "f"+string(rune('a'+randInt(t, 12)))+".bin")
		body := make([]byte, randInt(t, 4096))
		if _, err := rand.Read(body); err != nil {
			t.Fatalf("rand: %v", err)
		}
		if err := os.WriteFile(filepath.Join(root, rel), body, 0600); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
		want[rel] = body
	}
	return want
}

func readTree(t *testing.T, root string) map[string][]byte {
	t.Helper()
	got := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		body, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		got[rel] = body
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return got
}

func sortedKeysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestCopyDirRoundTripsEveryFile(t *testing.T) {
	for range 25 {
		base := t.TempDir()
		src := filepath.Join(base, "src")
		dst := filepath.Join(base, "dst")
		if err := os.MkdirAll(src, 0700); err != nil {
			t.Fatalf("mkdir src: %v", err)
		}

		want := buildRandomTree(t, src)
		if err := copyDir(src, dst); err != nil {
			t.Fatalf("copyDir: %v", err)
		}

		got := readTree(t, dst)
		wantKeys, gotKeys := sortedKeysOf(want), sortedKeysOf(got)
		if len(wantKeys) != len(gotKeys) {
			t.Fatalf("copied %d files, source had %d\nwant %v\ngot  %v",
				len(gotKeys), len(wantKeys), wantKeys, gotKeys)
		}
		for i := range wantKeys {
			if wantKeys[i] != gotKeys[i] {
				t.Fatalf("file %d: copied %q, source had %q", i, gotKeys[i], wantKeys[i])
			}
		}
		for rel, body := range want {
			if string(got[rel]) != string(body) {
				t.Fatalf("%s: %d bytes copied, source had %d", rel, len(got[rel]), len(body))
			}
		}
		if a, b := dirSize(src), dirSize(dst); a != b {
			t.Fatalf("dirSize disagrees after copy: src %d, dst %d", a, b)
		}
	}
}

func TestCopyDirPreservesEmptyDirectories(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src")
	dst := filepath.Join(base, "dst")
	for _, rel := range []string{"a/b/c", "a/empty", "solo"} {
		if err := os.MkdirAll(filepath.Join(src, rel), 0700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(src, "a/b/c/f.txt"), []byte("x"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := copyDir(src, dst); err != nil {
		t.Fatalf("copyDir: %v", err)
	}
	for _, rel := range []string{"a/b/c", "a/empty", "solo"} {
		st, err := os.Stat(filepath.Join(dst, rel))
		if err != nil || !st.IsDir() {
			t.Errorf("%s did not survive the copy (err=%v)", rel, err)
		}
	}
}

func TestCopyDirReportsAMissingSource(t *testing.T) {
	base := t.TempDir()
	if err := copyDir(filepath.Join(base, "absent"), filepath.Join(base, "dst")); err == nil {
		t.Error("copying a missing source must fail; mn mv would otherwise delete the original after a no-op copy")
	}
}

func TestDirSizeCountsFileBytesOnly(t *testing.T) {
	base := t.TempDir()
	if got := dirSize(base); got != 0 {
		t.Errorf("empty dir = %d bytes, want 0", got)
	}
	if err := os.MkdirAll(filepath.Join(base, "sub/deeper"), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if got := dirSize(base); got != 0 {
		t.Errorf("directories must not contribute bytes, got %d", got)
	}

	total := int64(0)
	for i, rel := range []string{"a.bin", "sub/b.bin", "sub/deeper/c.bin"} {
		body := make([]byte, (i+1)*100)
		if err := os.WriteFile(filepath.Join(base, rel), body, 0600); err != nil {
			t.Fatalf("write: %v", err)
		}
		total += int64(len(body))
	}
	if got := dirSize(base); got != total {
		t.Errorf("dirSize = %d, want %d (must recurse into every subdirectory)", got, total)
	}
}

func TestDirSizeOnAMissingPathIsZero(t *testing.T) {
	if got := dirSize(filepath.Join(t.TempDir(), "absent")); got != 0 {
		t.Errorf("missing path = %d, want 0", got)
	}
}

func TestCopyFileOverwritesAnExistingDestination(t *testing.T) {
	base := t.TempDir()
	src := filepath.Join(base, "src.bin")
	dst := filepath.Join(base, "dst.bin")
	if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := os.WriteFile(dst, []byte("much longer stale content"), 0600); err != nil {
		t.Fatalf("write dst: %v", err)
	}

	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	body, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "new" {
		t.Errorf("destination = %q, want %q with no stale tail", body, "new")
	}
}

func TestCopyFileReportsAMissingSource(t *testing.T) {
	base := t.TempDir()
	if err := copyFile(filepath.Join(base, "absent"), filepath.Join(base, "dst")); err == nil {
		t.Error("copying a missing file must report an error")
	}
}
