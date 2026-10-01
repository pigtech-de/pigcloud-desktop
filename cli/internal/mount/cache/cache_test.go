package cache

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/fsutil"
)

func TestDBOpenAndMigrate(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	inode := &Inode{
		RemotePath:  "Documents/test.txt",
		DisplayName: "test.txt",
		IsDir:       false,
		Size:        1024,
		Mtime:       1000,
		SyncStatus:  StatusSynced,
	}
	id, err := db.UpsertInode(inode)
	if err != nil {
		t.Fatalf("UpsertInode: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero ID")
	}

	got, err := db.GetInodeByPath("Documents/test.txt")
	if err != nil {
		t.Fatalf("GetInodeByPath: %v", err)
	}
	if got.DisplayName != "test.txt" {
		t.Fatalf("expected test.txt, got %s", got.DisplayName)
	}
	if got.Size != 1024 {
		t.Fatalf("expected size 1024, got %d", got.Size)
	}

	inode.Size = 2048
	id2, err := db.UpsertInode(inode)
	if err != nil {
		t.Fatalf("UpsertInode update: %v", err)
	}
	if id2 != id {
		t.Fatalf("upsert on the same path must return the same ID: got %d, want %d", id2, id)
	}

	got2, _ := db.GetInodeByPath("Documents/test.txt")
	if got2.Size != 2048 {
		t.Fatalf("expected size 2048 after update, got %d", got2.Size)
	}

	if err := db.MarkDirty(id); err != nil {
		t.Fatalf("MarkDirty: %v", err)
	}
	got3, _ := db.GetInodeByPath("Documents/test.txt")
	if !got3.Dirty {
		t.Fatal("expected dirty after MarkDirty")
	}
	if got3.SyncStatus != StatusPending {
		t.Fatalf("expected pending status, got %s", got3.SyncStatus)
	}

	if err := db.MarkSynced(id, "etag-123"); err != nil {
		t.Fatalf("MarkSynced: %v", err)
	}
	got4, _ := db.GetInodeByPath("Documents/test.txt")
	if got4.Dirty {
		t.Fatal("expected not dirty after MarkSynced")
	}
	if got4.SyncStatus != StatusSynced {
		t.Fatalf("expected synced status, got %s", got4.SyncStatus)
	}

	if err := db.DeleteInode("Documents/test.txt"); err != nil {
		t.Fatalf("DeleteInode: %v", err)
	}
	_, err = db.GetInodeByPath("Documents/test.txt")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestDBWritebackQueue(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	if err := db.EnqueueWriteback(1, "upload", "test.txt", ""); err != nil {
		t.Fatalf("EnqueueWriteback: %v", err)
	}
	if err := db.EnqueueWriteback(2, "mkdir", "newdir", ""); err != nil {
		t.Fatalf("EnqueueWriteback: %v", err)
	}

	count, _ := db.PendingWritebackCount()
	if count != 2 {
		t.Fatalf("expected 2 pending, got %d", count)
	}

	entries, err := db.DequeueWriteback(10, 0)
	if err != nil {
		t.Fatalf("DequeueWriteback: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Action != "upload" {
		t.Fatalf("expected upload, got %s", entries[0].Action)
	}

	if again, _ := db.DequeueWriteback(10, 0); len(again) != 0 {
		t.Fatalf("expected 0 entries on re-dequeue (already claimed), got %d", len(again))
	}
	if c, _ := db.PendingWritebackCount(); c != 0 {
		t.Fatalf("expected 0 pending after claim, got %d", c)
	}

	n, err := db.RequeueInProgress()
	if err != nil {
		t.Fatalf("RequeueInProgress: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 requeued, got %d", n)
	}
	if c, _ := db.PendingWritebackCount(); c != 2 {
		t.Fatalf("expected 2 pending after requeue, got %d", c)
	}

	entries, _ = db.DequeueWriteback(10, 0)
	db.DeleteWriteback(entries[0].ID)
	db.UpdateWriteback(entries[1].ID, "pending", "", entries[1].Attempts)
	count, _ = db.PendingWritebackCount()
	if count != 1 {
		t.Fatalf("expected 1 pending after delete, got %d", count)
	}
}

func TestUpsertStableIDAcrossConnections(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	inode := &Inode{RemotePath: "a.txt", DisplayName: "a.txt", SyncStatus: StatusSynced}
	id, err := db.UpsertInode(inode)
	if err != nil {
		t.Fatalf("UpsertInode: %v", err)
	}

	for range 5 {
		db.EnqueueWriteback(id, "upload", "a.txt", "")
	}

	inode.Size = 99
	id2, err := db.UpsertInode(inode)
	if err != nil {
		t.Fatalf("UpsertInode update: %v", err)
	}
	if id2 != id {
		t.Fatalf("update-path upsert returned wrong ID: got %d, want %d", id2, id)
	}
}

func TestUpsertPreservesPinAndAccess(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	id, _ := db.UpsertInode(&Inode{RemotePath: "p.txt", DisplayName: "p.txt", SyncStatus: StatusSynced})
	db.SetPinned("p.txt", true)
	db.MarkCached(id, "hash-1")
	db.MarkSynced(id, "etag-1")

	db.UpsertInode(&Inode{RemotePath: "p.txt", DisplayName: "p.txt", Size: 5, SyncStatus: StatusPending})

	got, _ := db.GetInodeByPath("p.txt")
	if !got.Pinned {
		t.Fatal("pin lost after metadata upsert")
	}
	if got.LastAccess == 0 {
		t.Fatal("last_access reset after metadata upsert")
	}
	if got.Etag != "etag-1" {
		t.Fatalf("etag clobbered after metadata upsert: %q", got.Etag)
	}
}

func TestSetInodeSize(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	id, _ := db.UpsertInode(&Inode{RemotePath: "legacy.dat", DisplayName: "legacy.dat", Size: 0, SyncStatus: StatusSynced})
	if err := db.SetInodeSize(id, 4096); err != nil {
		t.Fatalf("SetInodeSize: %v", err)
	}
	got, _ := db.GetInode(id)
	if got == nil || got.Size != 4096 {
		t.Fatalf("size = %v, want 4096 persisted", got)
	}
}

func TestUpsertPreservesDirtyFlag(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	id, _ := db.UpsertInode(&Inode{RemotePath: "e.txt", DisplayName: "e.txt", Size: 10, Dirty: true, SyncStatus: StatusPending})

	db.UpsertInode(&Inode{RemotePath: "e.txt", DisplayName: "e.txt", Size: 10, Dirty: false, SyncStatus: StatusSynced})

	got, _ := db.GetInode(id)
	if got == nil || !got.Dirty {
		t.Fatalf("dirty = %v, want true (persisted pending edit survived the rebuild)", got)
	}

	db.MarkSynced(id, "")
	if got, _ := db.GetInode(id); got.Dirty {
		t.Error("MarkSynced did not clear dirty")
	}
}

func TestStoreConcurrentPutSameContent(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := make([]byte, 3*1024*1024+7)
	for i := range data {
		data[i] = byte(i * 7)
	}

	var wg sync.WaitGroup
	hashes := make([]string, 16)
	for i := range 16 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			h, err := store.Put(data)
			if err != nil {
				t.Errorf("Put: %v", err)
				return
			}
			hashes[idx] = h
		}(i)
	}
	wg.Wait()

	for _, h := range hashes {
		if h != hashes[0] {
			t.Fatalf("content-addressed hashes diverged: %s vs %s", h, hashes[0])
		}
	}
	got, err := store.Get(hashes[0])
	if err != nil {
		t.Fatalf("Get after concurrent Put: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("blob corrupted: got %d bytes, want %d", len(got), len(data))
	}
}

type boundedWriter struct {
	t   *testing.T
	w   io.Writer
	max int
	tag string
}

func (b *boundedWriter) Write(p []byte) (int, error) {
	if len(p) > b.max {
		b.t.Fatalf("%s wrote %d bytes in one Write, over the %d bound (whole-file buffer?)", b.tag, len(p), b.max)
	}
	return b.w.Write(p)
}

type boundedReader struct {
	t   *testing.T
	r   io.Reader
	max int
	tag string
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if len(p) > b.max {
		b.t.Fatalf("%s read into a %d-byte buffer, over the %d bound (whole-file buffer?)", b.tag, len(p), b.max)
	}
	return b.r.Read(p)
}

func TestStoreWriteToStreamsWholeBlob(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	sizes := []int{0, 1, cacheChunkSize - 1, cacheChunkSize, cacheChunkSize + 1, 3*cacheChunkSize + 123}
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*31 + 7)
		}
		hash, err := store.Put(data)
		if err != nil {
			t.Fatalf("Put(%d): %v", size, err)
		}

		var buf bytes.Buffer
		bw := &boundedWriter{t: t, w: &buf, max: cacheChunkSize, tag: "WriteTo"}
		n, err := store.WriteTo(hash, bw)
		if err != nil {
			t.Fatalf("WriteTo(%d): %v", size, err)
		}
		if n != int64(size) {
			t.Errorf("WriteTo(%d) reported %d bytes", size, n)
		}
		if !bytes.Equal(buf.Bytes(), data) {
			t.Errorf("WriteTo(%d) content mismatch", size)
		}
		if got, _ := store.Get(hash); !bytes.Equal(buf.Bytes(), got) {
			t.Errorf("WriteTo(%d) diverges from Get", size)
		}
	}
}

func TestStoreSealStreamIsChunkBounded(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := make([]byte, 3*cacheChunkSize+123)
	for i := range data {
		data[i] = byte(i*13 + 5)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(data))

	br := &boundedReader{t: t, r: bytes.NewReader(data), max: cacheChunkSize, tag: "sealStream ingest"}
	var out bytes.Buffer
	bw := &boundedWriter{t: t, w: &out, max: cacheChunkSize + 128, tag: "sealStream output"}
	n, err := store.sealStream(br, hash, bw)
	if err != nil {
		t.Fatalf("sealStream: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("sealStream sealed %d bytes, want %d", n, len(data))
	}
}

func TestStorePutFileMatchesPut(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	srcDir := t.TempDir()
	sizes := []int{0, 1, cacheChunkSize - 1, cacheChunkSize, cacheChunkSize + 1, 3*cacheChunkSize + 77}
	for _, size := range sizes {
		data := make([]byte, size)
		for i := range data {
			data[i] = byte(i*17 + 3)
		}
		src := filepath.Join(srcDir, fmt.Sprintf("f-%d.bin", size))
		if err := os.WriteFile(src, data, 0600); err != nil {
			t.Fatal(err)
		}

		fileHash, err := store.PutFile(src)
		if err != nil {
			t.Fatalf("PutFile(%d): %v", size, err)
		}
		memHash, err := store.Put(data)
		if err != nil {
			t.Fatalf("Put(%d): %v", size, err)
		}
		if fileHash != memHash {
			t.Errorf("size %d: PutFile hash %s != Put hash %s", size, fileHash, memHash)
		}
		got, err := store.Get(fileHash)
		if err != nil {
			t.Fatalf("Get(%d): %v", size, err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("size %d: PutFile blob does not round-trip", size)
		}
	}
}

func TestDBSyncStatusTracking(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	for _, tc := range []struct {
		path   string
		status SyncStatus
		reason string
	}{
		{"good.txt", StatusSynced, ""},
		{"bad.exe", StatusRejected, "file type .exe is not supported"},
		{"failed.zip", StatusFailed, "upload quota exceeded"},
		{"conflict.txt", StatusConflict, "both sides changed"},
	} {
		inode := &Inode{
			RemotePath:   tc.path,
			DisplayName:  tc.path,
			SyncStatus:   tc.status,
			StatusReason: tc.reason,
		}
		db.UpsertInode(inode)
	}

	issues, err := db.ListIssues()
	if err != nil {
		t.Fatalf("ListIssues: %v", err)
	}
	if len(issues) != 3 {
		t.Fatalf("expected 3 issues, got %d", len(issues))
	}

	counts, _ := db.CountByStatus()
	if counts[StatusSynced] != 1 {
		t.Fatalf("expected 1 synced, got %d", counts[StatusSynced])
	}
	if counts[StatusRejected] != 1 {
		t.Fatalf("expected 1 rejected, got %d", counts[StatusRejected])
	}

	hashes, err := db.DeleteRejected()
	if err != nil {
		t.Fatalf("DeleteRejected: %v", err)
	}
	_ = hashes

	issues2, _ := db.ListIssues()
	if len(issues2) != 2 {
		t.Fatalf("expected 2 issues after cleaning rejected, got %d", len(issues2))
	}
}

func TestStoreEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := []byte("Hello, PigCloud mount! This is a test of the cache encryption layer.")
	hash, err := store.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	if !store.Has(hash) {
		t.Fatal("Has returned false")
	}

	got, err := store.Get(hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("data mismatch: got %q, want %q", string(got), string(data))
	}

	partial, err := store.ReadAt(hash, 7, 8)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if string(partial) != "PigCloud" {
		t.Fatalf("ReadAt mismatch: got %q, want %q", string(partial), "PigCloud")
	}

	storeDir := filepath.Join(dir, "store")
	entries, _ := os.ReadDir(storeDir)
	if len(entries) == 0 {
		t.Fatal("no shard directories in store")
	}
	rawPath := store.pathFor(hash)
	raw, err := os.ReadFile(rawPath)
	if err != nil {
		t.Fatalf("ReadFile raw: %v", err)
	}
	if string(raw) == string(data) {
		t.Fatal("on-disk content is plaintext — encryption-at-rest failed")
	}
	t.Logf("Store OK: %d bytes plaintext → %d bytes encrypted on disk", len(data), len(raw))

	store.Remove(hash)
	if store.Has(hash) {
		t.Fatal("Has returned true after Remove")
	}
}

func TestStoreLargeFile(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := make([]byte, 2*1024*1024+512*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	hash, err := store.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Get(hash)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != len(data) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(data))
	}
	for i := range data {
		if got[i] != data[i] {
			t.Fatalf("byte mismatch at offset %d: got %d, want %d", i, got[i], data[i])
		}
	}

	off := int64(1024*1024 + 100)
	size := 500
	partial, err := store.ReadAt(hash, off, size)
	if err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	expected := data[off : off+int64(size)]
	if string(partial) != string(expected) {
		t.Fatalf("ReadAt mismatch at offset %d", off)
	}
	t.Logf("Large file OK: %d bytes, multi-chunk encrypt/decrypt verified", len(data))
}

func TestReadAtBoundariesAndCache(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := make([]byte, 2*cacheChunkSize+cacheChunkSize/2)
	for i := range data {
		data[i] = byte((i*131 + 7) % 251)
	}
	hash, err := store.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	check := func(off int64, size int) {
		got, err := store.ReadAt(hash, off, size)
		if err != nil {
			t.Fatalf("ReadAt(%d,%d): %v", off, size, err)
		}
		end := min(off+int64(size), int64(len(data)))
		want := data[off:end]
		if string(got) != string(want) {
			t.Fatalf("ReadAt(%d,%d) mismatch: got %d bytes, want %d", off, size, len(got), len(want))
		}
	}

	check(0, 64*1024)
	check(cacheChunkSize-100, 200)
	check(cacheChunkSize-100, 200)
	check(2*cacheChunkSize+1000, 5000)
	check(int64(len(data))-10, 10)
	check(2*cacheChunkSize, cacheChunkSize)

	if got, _ := store.ReadAt(hash, int64(len(data))+100, 50); len(got) != 0 {
		t.Fatalf("read past EOF returned %d bytes, want 0", len(got))
	}
}

func TestStoreBlobSwapRejected(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	a := make([]byte, 100)
	b := make([]byte, 100)
	for i := range b {
		b[i] = 0xAB
	}
	hashA, _ := store.Put(a)
	hashB, _ := store.Put(b)

	bBytes, err := os.ReadFile(store.pathFor(hashB))
	if err != nil {
		t.Fatalf("read blob B: %v", err)
	}
	if err := os.WriteFile(store.pathFor(hashA), bBytes, 0600); err != nil {
		t.Fatalf("swap blob: %v", err)
	}

	if _, err := store.Get(hashA); err == nil {
		t.Fatal("Get returned B's content under A's hash — AD swap not detected")
	}
	if _, err := store.ReadAt(hashA, 0, 100); err == nil {
		t.Fatal("ReadAt returned B's content under A's hash — AD swap not detected")
	}
}

func TestStoreTruncatedBlobErrors(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := make([]byte, cacheChunkSize+500*1024)
	hash, _ := store.Put(data)

	if err := os.Truncate(store.pathFor(hash), int64(fullRecordSize)+2); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	if _, err := store.ReadAt(hash, cacheChunkSize+10, 100); err == nil {
		t.Fatal("ReadAt over a torn chunk returned no error")
	}
}

func TestEviction(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	evictor := NewEvictor(db, store, 500)

	for i, name := range []string{"a.txt", "b.txt", "c.txt"} {
		data := bytes.Repeat([]byte{byte('a' + i)}, 200)
		hash, _ := store.Put(data)
		inode := &Inode{
			RemotePath:  name,
			DisplayName: name,
			Size:        200,
			Cached:      true,
			ContentHash: hash,
			LastAccess:  int64(i),
			SyncStatus:  StatusSynced,
		}
		db.UpsertInode(inode)
	}

	evicted, err := evictor.RunIfNeeded()
	if err != nil {
		t.Fatalf("RunIfNeeded: %v", err)
	}
	if evicted == 0 {
		t.Fatal("expected at least 1 eviction")
	}
	t.Logf("Evicted %d files (target was 90%% of 500 = 450 bytes)", evicted)

	a, _ := db.GetInodeByPath("a.txt")
	if a.Cached {
		t.Fatal("expected a.txt to be evicted (oldest)")
	}
}

func TestReleaseBlobRefcount(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	data := []byte("shared content across two files")
	hash, _ := store.Put(data)

	id1, _ := db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Cached: true, ContentHash: hash, SyncStatus: StatusSynced})
	id2, _ := db.UpsertInode(&Inode{RemotePath: "b.txt", DisplayName: "b.txt", Cached: true, ContentHash: hash, SyncStatus: StatusSynced})

	ReleaseBlob(db, store, hash, id1)
	db.InvalidateCache(id1)
	if !store.Has(hash) {
		t.Fatal("blob removed while another inode still references it")
	}
	if _, err := store.Get(hash); err != nil {
		t.Fatalf("survivor can't read shared blob: %v", err)
	}

	ReleaseBlob(db, store, hash, id2)
	db.InvalidateCache(id2)
	if store.Has(hash) {
		t.Fatal("blob not removed after last reference dropped")
	}
}

func TestGCOrphans(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	keep, _ := store.Put([]byte("referenced content"))
	db.UpsertInode(&Inode{RemotePath: "a.txt", DisplayName: "a.txt", Cached: true, ContentHash: keep, SyncStatus: StatusSynced})

	orphan, _ := store.Put([]byte("orphan content nobody references"))

	swept, err := GCOrphans(db, store)
	if err != nil {
		t.Fatalf("GCOrphans: %v", err)
	}
	if swept.Blobs != 1 {
		t.Fatalf("removed %d blobs, want 1", swept.Blobs)
	}
	if swept.Temps != 0 {
		t.Fatalf("removed %d temp files with none seeded, want 0", swept.Temps)
	}
	if !store.Has(keep) {
		t.Fatal("referenced blob was removed")
	}
	if store.Has(orphan) {
		t.Fatal("orphan blob survived GC")
	}
}

func TestMigrateReopenIdempotent(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id, err := db.UpsertInode(&Inode{RemotePath: "f.txt", DisplayName: "f.txt", SyncStatus: StatusSynced})
	if err != nil {
		t.Fatalf("UpsertInode: %v", err)
	}
	db.Close()

	db2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	got, err := db2.GetInode(id)
	if err != nil || got == nil || got.RemotePath != "f.txt" {
		t.Fatalf("row lost across reopen: got=%v err=%v", got, err)
	}
}

func TestParseCacheSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"5G", 5 * 1024 * 1024 * 1024},
		{"500M", 500 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"100K", 100 * 1024},
		{"10GB", 10 * 1024 * 1024 * 1024},
	}
	for _, tc := range tests {
		got, err := ParseCacheSize(tc.input)
		if err != nil {
			t.Errorf("ParseCacheSize(%q): %v", tc.input, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseCacheSize(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}

	for _, bad := range []string{"10XYZ", "5furlongs", "abc", "1.2.3G", "-5G", "0", "G", "10GG"} {
		if _, err := ParseCacheSize(bad); err == nil {
			t.Errorf("ParseCacheSize(%q): expected error, got nil", bad)
		}
	}
}

func diskBytes(t *testing.T, dir string) int64 {
	t.Helper()
	var total int64
	err := filepath.WalkDir(filepath.Join(dir, "store"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || fsutil.IsTempName(d.Name()) {
			return nil
		}
		info, ierr := d.Info()
		if ierr == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk store: %v", err)
	}
	return total
}

func TestCacheBytesMeasuresDiskNotInodeSizes(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	shared := bytes.Repeat([]byte("s"), 3<<20)
	sharedHash, err := store.Put(shared)
	if err != nil {
		t.Fatalf("put shared: %v", err)
	}
	for _, name := range []string{"one.bin", "copy-of-one.bin"} {
		if _, err := db.UpsertInode(&Inode{
			RemotePath: name, DisplayName: name, Size: int64(len(shared)),
			Cached: true, ContentHash: sharedHash, SyncStatus: StatusSynced,
		}); err != nil {
			t.Fatalf("upsert %s: %v", name, err)
		}
	}

	orphanHash, err := store.Put(bytes.Repeat([]byte("o"), 1<<20))
	if err != nil {
		t.Fatalf("put orphan: %v", err)
	}

	if got, want := CacheBytes(db, store), diskBytes(t, dir); got != want {
		t.Errorf("CacheBytes = %d, on disk = %d", got, want)
	}
	byInode, _ := db.TotalCacheSize()
	if byInode == CacheBytes(db, store) {
		t.Fatal("fixture does not separate inode sizes from disk bytes")
	}

	before := CacheBytes(db, store)
	if _, err := store.Put(shared); err != nil {
		t.Fatalf("re-put shared: %v", err)
	}
	if got := CacheBytes(db, store); got != before {
		t.Errorf("re-putting stored content moved the total from %d to %d", before, got)
	}

	if err := store.Remove(orphanHash); err != nil {
		t.Fatalf("remove orphan: %v", err)
	}
	if got, want := CacheBytes(db, store), diskBytes(t, dir); got != want {
		t.Errorf("after a removal CacheBytes = %d, on disk = %d", got, want)
	}

	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	if got, want := reopened.Bytes(), diskBytes(t, dir); got != want {
		t.Errorf("reopened store Bytes = %d, on disk = %d", got, want)
	}
}

func TestCacheBytesSurvivesConcurrentPutsAndRemoves(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	const rounds = 60
	var wg sync.WaitGroup
	hashes := make([]string, rounds)
	for i := range rounds {
		content := bytes.Repeat([]byte{byte(i)}, 4096+i)
		h, err := store.Put(content)
		if err != nil {
			t.Fatalf("seed put %d: %v", i, err)
		}
		hashes[i] = h
	}

	start := make(chan struct{})
	for i := range rounds {
		content := bytes.Repeat([]byte{byte(i)}, 4096+i)
		h := hashes[i]
		wg.Add(3)
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				store.Put(content)
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			for range 20 {
				store.Remove(h)
			}
		}()
		go func(i int) {
			defer wg.Done()
			<-start
			for n := range 20 {
				fresh := bytes.Repeat([]byte{byte(i), byte(n)}, 512+n)
				store.Put(fresh)
				if n%3 == 0 {
					store.Remove(fmt.Sprintf("%x", sha256.Sum256(fresh)))
				}
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if got, want := store.Bytes(), diskBytes(t, dir); got != want {
		t.Errorf("counter = %d after concurrent rounds, on disk = %d (drift %+d)", got, want, got-want)
	}
}

func TestRemoveTakesTheStoreLock(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	content := bytes.Repeat([]byte("p"), 8192)
	hash, err := store.Put(content)
	if err != nil {
		t.Fatal(err)
	}

	store.mu.Lock()
	removed := make(chan struct{})
	go func() {
		store.Remove(hash)
		close(removed)
	}()

	select {
	case <-removed:
		store.mu.Unlock()
		t.Fatal("Remove completed while the store lock was held: its stat-then-delete can straddle a concurrent commit")
	case <-time.After(200 * time.Millisecond):
	}
	store.mu.Unlock()

	select {
	case <-removed:
	case <-time.After(5 * time.Second):
		t.Fatal("Remove never completed after the lock was released")
	}

	if got, want := store.Bytes(), diskBytes(t, dir); got != want {
		t.Errorf("counter = %d, on disk = %d", got, want)
	}
}

func TestBytesResyncsRatherThanClampingCorruption(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer store.Close()

	if _, err := store.Put(bytes.Repeat([]byte("x"), 12000)); err != nil {
		t.Fatal(err)
	}
	real := diskBytes(t, dir)
	if real == 0 {
		t.Fatal("fixture stored nothing")
	}

	store.bytes.Store(-1)
	if got := store.Bytes(); got != real {
		t.Errorf("Bytes() = %d with a corrupt counter, want a resync to %d", got, real)
	}
	if got := store.bytes.Load(); got != real {
		t.Errorf("the corrupt counter was not repaired: %d", got)
	}
}
