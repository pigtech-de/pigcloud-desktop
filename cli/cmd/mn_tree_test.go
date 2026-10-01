package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/mount/cache"
)

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	saved := os.Stdout
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()

	fn()

	os.Stdout = saved
	w.Close()
	out := <-done
	r.Close()
	return out
}

func inode(remotePath string, isDir bool, status cache.SyncStatus) *cache.Inode {
	name := remotePath
	if i := strings.LastIndex(remotePath, "/"); i >= 0 {
		name = remotePath[i+1:]
	}
	return &cache.Inode{RemotePath: remotePath, DisplayName: name, IsDir: isDir, SyncStatus: status}
}

func nonEmptyLines(s string) []string {
	var out []string
	for l := range strings.SplitSeq(s, "\n") {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestPrintInodeTreeNeverDropsAnInode(t *testing.T) {
	inodes := []*cache.Inode{
		inode("Photos", true, cache.StatusSynced),
		inode("Photos/2026", true, cache.StatusSynced),
		inode("Photos/2026/a.jpg", false, cache.StatusPending),
		inode("Photos/b.jpg", false, cache.StatusSynced),
		inode("Docs", true, cache.StatusSynced),
		inode("Docs/notes.txt", false, cache.StatusConflict),
		inode("loose.txt", false, cache.StatusFailed),
	}

	out := captureStdout(t, func() { printInodeTree(inodes) })
	lines := nonEmptyLines(out)
	if len(lines) != len(inodes) {
		t.Fatalf("printed %d lines for %d inodes:\n%s", len(lines), len(inodes), out)
	}
	for _, in := range inodes {
		if !strings.Contains(out, in.DisplayName) {
			t.Errorf("%q never reached the output:\n%s", in.RemotePath, out)
		}
	}
	if !strings.Contains(out, "└── ") || !strings.Contains(out, "├── ") {
		t.Errorf("no box-drawing connectors rendered:\n%s", out)
	}
	if !strings.Contains(out, "Photos/") {
		t.Errorf("directories must carry a trailing slash:\n%s", out)
	}
	if !strings.Contains(out, "conflict") || !strings.Contains(out, "failed") {
		t.Errorf("sync statuses were dropped:\n%s", out)
	}
}

func TestPrintInodeTreeReRootsOrphansInsteadOfDroppingThem(t *testing.T) {
	cases := [][]*cache.Inode{
		{inode("Photos/2026/a.jpg", false, cache.StatusSynced)},
		{
			inode("Photos/a.jpg", false, cache.StatusSynced),
			inode("Photos", true, cache.StatusSynced),
		},
		{
			inode("a/b/c/d.txt", false, cache.StatusPending),
			inode("a", true, cache.StatusSynced),
			inode("a/b/c", true, cache.StatusSynced),
		},
	}
	for i, set := range cases {
		out := captureStdout(t, func() { printInodeTree(set) })
		if got := len(nonEmptyLines(out)); got != len(set) {
			t.Errorf("case %d: printed %d lines for %d inodes:\n%s", i, got, len(set), out)
		}
	}
}

func TestPrintInodeTreeTerminatesOnRandomOrderings(t *testing.T) {
	paths := []string{"a", "a/b", "a/b/c", "a/b/c/d.txt", "a/x.txt", "z", "z/y.txt", "solo.bin"}
	for range 200 {
		shuffled := make([]*cache.Inode, len(paths))
		for i, p := range paths {
			shuffled[i] = inode(p, !strings.Contains(p, "."), cache.StatusSynced)
		}
		for i := len(shuffled) - 1; i > 0; i-- {
			j := randInt(t, i+1)
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}

		out := captureStdout(t, func() { printInodeTree(shuffled) })
		if got := len(nonEmptyLines(out)); got != len(paths) {
			t.Fatalf("ordering %v printed %d lines for %d inodes:\n%s",
				pathsOf(shuffled), got, len(paths), out)
		}
	}
}

func pathsOf(inodes []*cache.Inode) []string {
	out := make([]string, 0, len(inodes))
	for _, i := range inodes {
		out = append(out, i.RemotePath)
	}
	return out
}

func TestPrintInodeTreeAlignsOnRuneWidthNotByteLength(t *testing.T) {
	set := []*cache.Inode{
		inode("dir", true, cache.StatusSynced),
		inode("dir/deep", true, cache.StatusSynced),
		inode("dir/deep/file.txt", false, cache.StatusPending),
		inode("short.txt", false, cache.StatusSynced),
	}
	out := captureStdout(t, func() { printInodeTree(set) })

	var cols []int
	for _, line := range nonEmptyLines(out) {
		idx := -1
		for _, status := range []string{"synced", "pending"} {
			if i := strings.Index(line, status); i >= 0 && (idx < 0 || i < idx) {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("line has no status: %q", line)
		}
		cols = append(cols, runeIndex(line, idx))
	}
	for i := 1; i < len(cols); i++ {
		if cols[i] != cols[0] {
			t.Errorf("status column drifts: line 0 at rune %d, line %d at rune %d\n%s",
				cols[0], i, cols[i], out)
		}
	}
}

func runeIndex(s string, byteIdx int) int {
	return len([]rune(s[:byteIdx]))
}

func TestPrintInodeListShowsStatusReasons(t *testing.T) {
	failed := inode("a/broken.bin", false, cache.StatusFailed)
	failed.StatusReason = "signature verification failed"
	set := []*cache.Inode{
		inode("a", true, cache.StatusSynced),
		failed,
	}

	out := captureStdout(t, func() { printInodeList(set, false) })
	if !strings.Contains(out, "signature verification failed") {
		t.Errorf("the reason a transfer failed must reach the user:\n%s", out)
	}
	if !strings.Contains(out, "D a") {
		t.Errorf("directories carry the D marker:\n%s", out)
	}
	if got := len(nonEmptyLines(out)); got != 2 {
		t.Errorf("printed %d lines for 2 inodes:\n%s", got, out)
	}
}

func TestPrintInodeListHandlesAnEmptySet(t *testing.T) {
	out := captureStdout(t, func() { printInodeList(nil, false) })
	if strings.TrimSpace(out) != "" {
		t.Errorf("an empty set must print nothing, got %q", out)
	}
	out = captureStdout(t, func() { printInodeTree(nil) })
	if strings.TrimSpace(out) != "" {
		t.Errorf("an empty tree must print nothing, got %q", out)
	}
}

func TestTailLinesStripsCarriageReturnsAndHandlesAnEmptyLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crlf.log")
	if err := os.WriteFile(path, []byte("one\r\ntwo\r\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := tailLines(path, 5)
	if len(got) != 2 {
		t.Fatalf("tailLines = %v, want 2 lines", got)
	}
	for i, want := range []string{"one", "two"} {
		if got[i] != want {
			t.Errorf("line %d = %q, want %q with no trailing CR", i, got[i], want)
		}
	}

	empty := filepath.Join(dir, "empty.log")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := tailLines(empty, 5); len(got) != 0 {
		t.Errorf("a log that exists but is empty must yield no lines, got %v", got)
	}
}
