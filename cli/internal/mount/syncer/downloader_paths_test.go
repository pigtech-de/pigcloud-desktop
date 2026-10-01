package syncer

import (
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/mount/vfs"
)

func TestWritebackLocalPath(t *testing.T) {
	syncDir := t.TempDir()
	w := &WritebackProcessor{vfs: &vfs.VFS{RemoteBase: "Base"}, syncDir: syncDir}

	if _, ok := (&WritebackProcessor{vfs: &vfs.VFS{}}).localPath("a.txt"); ok {
		t.Error("virtual mode (no sync dir) resolved a local path")
	}
	if _, ok := w.localPath(""); ok {
		t.Error("empty remote path resolved")
	}

	p, ok := w.localPath("Base/Docs/a.txt")
	if !ok || p != filepath.Join(syncDir, "Docs", "a.txt") {
		t.Errorf("base-prefixed path: %q %v", p, ok)
	}
	p, ok = w.localPath("other.txt")
	if !ok || p != filepath.Join(syncDir, "other.txt") {
		t.Errorf("unprefixed path: %q %v", p, ok)
	}

	if _, ok := w.localPath("Base/../../../etc/passwd"); ok {
		t.Error("escape via .. resolved inside the sync dir")
	}
}

func newPathDownloader(t *testing.T, remotePath string) *Downloader {
	t.Helper()
	return NewDownloader(t.TempDir(), remotePath, nil, nil, nil, &sync.Map{})
}

func TestDownloaderLocalPath(t *testing.T) {
	d := newPathDownloader(t, "Photos")

	p, ok := d.LocalPath("Photos/2024/a.jpg")
	if !ok || p != filepath.Join(d.syncDir, "2024", "a.jpg") {
		t.Errorf("prefixed: %q %v", p, ok)
	}
	if _, ok := d.LocalPath("Photos/../../evil"); ok {
		t.Error("escape resolved")
	}

	root := newPathDownloader(t, "/")
	p, ok = root.LocalPath("Docs/x.txt")
	if !ok || p != filepath.Join(root.syncDir, "Docs", "x.txt") {
		t.Errorf("root mount: %q %v", p, ok)
	}
}

func TestDownloaderPathToRemote(t *testing.T) {
	d := newPathDownloader(t, "Photos")
	if got := d.pathToRemote(filepath.Join(d.syncDir, "2024", "a.jpg")); got != "Photos/2024/a.jpg" {
		t.Errorf("nested: %q", got)
	}
	if got := d.pathToRemote(d.syncDir); got != "Photos" {
		t.Errorf("sync root maps to the mount target: %q", got)
	}

	root := newPathDownloader(t, "/")
	if got := root.pathToRemote(filepath.Join(root.syncDir, "a.txt")); got != "a.txt" {
		t.Errorf("root mount: %q", got)
	}
}

func TestSuppressPathExpires(t *testing.T) {
	d := newPathDownloader(t, "Photos")
	p := filepath.Join(d.syncDir, "f.txt")
	d.SuppressPath(p, 30*time.Millisecond)
	if _, ok := d.suppress.Load(p); !ok {
		t.Fatal("path not suppressed")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := d.suppress.Load(p); !ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("suppression never expired")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestShouldIgnoreTracksLists(t *testing.T) {
	for name := range ignoredNames {
		if !shouldIgnore(name) {
			t.Errorf("listed name %q not ignored", name)
		}
	}
	for _, prefix := range ignoredPrefixes {
		if !shouldIgnore(prefix + "anything") {
			t.Errorf("prefix %q not ignored", prefix)
		}
	}
	for _, suffix := range ignoredSuffixes {
		if !shouldIgnore("file" + suffix) {
			t.Errorf("suffix %q not ignored", suffix)
		}
	}

	for _, hidden := range []string{".git", ".hidden", ".envrc"} {
		if !shouldIgnore(hidden) {
			t.Errorf("hidden file %q not ignored", hidden)
		}
	}
	for _, name := range []string{".", "..", "normal.txt", "Bericht 2024.pdf", "tmp-not-suffix"} {
		if shouldIgnore(name) {
			t.Errorf("%q wrongly ignored", name)
		}
	}
}
