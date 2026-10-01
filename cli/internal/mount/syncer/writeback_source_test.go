package syncer

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/crypto"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

var (
	_ func(string) (string, func(), error) = (*WritebackProcessor)(nil).streamStoreToTemp
	_ func([]byte) (string, func(), error) = writeTempPlaintext
)

type stagingEnv struct {
	w       *WritebackProcessor
	db      *cache.DB
	store   *cache.Store
	syncDir string
	blobDir string
	tmpDir  string
}

func newStagingEnv(t *testing.T) *stagingEnv {
	t.Helper()
	syncDir := t.TempDir()
	tmpDir := t.TempDir()

	cacheDir := filepath.Join(syncDir, ".pigcloud")
	db, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	blobDir := filepath.Join(cacheDir, "blobs")
	store, err := cache.NewStore(blobDir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(store.Close)

	pub, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	v := vfs.New("", db, store, nil, nil, pub, nil, nil, nil, nil)

	t.Setenv("TMPDIR", tmpDir)
	t.Setenv("TMP", tmpDir)
	t.Setenv("TEMP", tmpDir)

	return &stagingEnv{
		w:       NewWritebackProcessor(v, nil, db, store, syncDir),
		db:      db,
		store:   store,
		syncDir: syncDir,
		blobDir: blobDir,
		tmpDir:  tmpDir,
	}
}

func multiChunkBody() []byte {
	b := make([]byte, 2*1024*1024+4096)
	for i := range b {
		b[i] = byte(i*31 + 7)
	}
	return b
}

func (e *stagingEnv) storeBody(t *testing.T, name string, body []byte) (string, string) {
	t.Helper()
	local := filepath.Join(e.syncDir, name)
	if err := os.WriteFile(local, body, 0600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	hash, err := e.store.PutFile(local)
	if err != nil {
		t.Fatalf("PutFile: %v", err)
	}
	return hash, local
}

func stagedTemps(t *testing.T, dir string) int {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, "pigcloud-mount-ul-*"))
	if err != nil {
		t.Fatalf("glob temps: %v", err)
	}
	return len(m)
}

func onlyBlob(t *testing.T, blobDir string) string {
	t.Helper()
	var found []string
	err := filepath.WalkDir(blobDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk store: %v", err)
	}
	if len(found) != 1 {
		t.Fatalf("store holds %d files, want 1", len(found))
	}
	return found[0]
}

func TestStreamStoreToTempStagesMultiChunkBlob(t *testing.T) {
	e := newStagingEnv(t)
	body := multiChunkBody()
	hash, _ := e.storeBody(t, "big.bin", body)

	path, cleanup, err := e.w.streamStoreToTemp(hash)
	if err != nil {
		t.Fatalf("streamStoreToTemp: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read staged temp: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("staged %d bytes, want the blob's %d", len(got), len(body))
	}
	if strings.HasPrefix(path, e.syncDir) {
		t.Errorf("staged temp %q sits inside the sync folder", path)
	}
	if n := stagedTemps(t, e.tmpDir); n != 1 {
		t.Errorf("staged temps = %d, want 1", n)
	}
	cleanup()
	if n := stagedTemps(t, e.tmpDir); n != 0 {
		t.Errorf("cleanup left %d staged temp(s) behind", n)
	}
}

func TestStreamStoreToTempDiscardsPartialStage(t *testing.T) {
	e := newStagingEnv(t)
	hash, _ := e.storeBody(t, "big.bin", multiChunkBody())

	blob := onlyBlob(t, e.blobDir)
	raw, err := os.ReadFile(blob)
	if err != nil {
		t.Fatalf("read blob: %v", err)
	}
	raw[len(raw)-1] ^= 0xff
	if err := os.WriteFile(blob, raw, 0600); err != nil {
		t.Fatalf("rewrite blob: %v", err)
	}

	if _, _, err := e.w.streamStoreToTemp(hash); err == nil {
		t.Fatal("corrupt blob staged without an error")
	}
	if n := stagedTemps(t, e.tmpDir); n != 0 {
		t.Errorf("%d partial staging temp(s) survived a failed decrypt", n)
	}
}

func TestStreamStoreToTempReportsMissingBlob(t *testing.T) {
	e := newStagingEnv(t)

	if _, _, err := e.w.streamStoreToTemp(strings.Repeat("ab", 32)); err == nil {
		t.Fatal("missing blob staged without an error")
	}
	if n := stagedTemps(t, e.tmpDir); n != 0 {
		t.Errorf("%d staging temp(s) left behind for a missing blob", n)
	}
}

func TestWriteTempPlaintextSpillsVirtualBuffer(t *testing.T) {
	e := newStagingEnv(t)
	body := []byte("virtual-mode write buffer")

	path, cleanup, err := writeTempPlaintext(body)
	if err != nil {
		t.Fatalf("writeTempPlaintext: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read spilled temp: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("spilled %q, want %q", got, body)
	}
	if n := stagedTemps(t, e.tmpDir); n != 1 {
		t.Errorf("staged temps = %d, want 1", n)
	}
	cleanup()
	if n := stagedTemps(t, e.tmpDir); n != 0 {
		t.Errorf("cleanup left %d spilled temp(s) behind", n)
	}
}

func TestProcessUploadFallsBackToLiveLocalFile(t *testing.T) {
	e := newStagingEnv(t)
	body := multiChunkBody()
	if err := os.WriteFile(filepath.Join(e.syncDir, "big.bin"), body, 0600); err != nil {
		t.Fatalf("write local file: %v", err)
	}

	id, err := e.db.UpsertInode(&cache.Inode{
		RemotePath: "big.bin", DisplayName: "big.bin", Size: int64(len(body)),
		ContentHash: strings.Repeat("ab", 32), Dirty: true, SyncStatus: cache.StatusPending,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	entry := &cache.WritebackEntry{InodeID: id, Action: "upload", RemotePath: "big.bin"}
	_, err = e.w.processUpload(context.Background(), entry)
	if err == nil {
		t.Fatal("fixture: upload without signing keys reported success")
	}
	if !strings.Contains(err.Error(), "signing keys") {
		t.Fatalf("upload stopped before the signing-key check: %v", err)
	}
}

func TestProcessUploadWithoutAnySourceFails(t *testing.T) {
	e := newStagingEnv(t)

	id, err := e.db.UpsertInode(&cache.Inode{
		RemotePath: "gone.bin", DisplayName: "gone.bin", Size: 4096,
		ContentHash: strings.Repeat("ab", 32), Dirty: true, SyncStatus: cache.StatusPending,
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	entry := &cache.WritebackEntry{InodeID: id, Action: "upload", RemotePath: "gone.bin"}
	_, err = e.w.processUpload(context.Background(), entry)
	if err == nil {
		t.Fatal("upload with no source reported success")
	}
	if !strings.Contains(err.Error(), "no content to upload") {
		t.Fatalf("want the no-content refusal, got: %v", err)
	}
	if n := stagedTemps(t, e.tmpDir); n != 0 {
		t.Errorf("%d staging temp(s) left behind by a failed upload", n)
	}
}
