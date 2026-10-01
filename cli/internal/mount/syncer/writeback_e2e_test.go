package syncer

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestWritebackE2E(t *testing.T) {
	if os.Getenv("PIGCLOUD_MOUNT_E2E") == "" {
		t.Skip("set PIGCLOUD_MOUNT_E2E=1 (with a logged-in, unlocked CLI) to run the mount writeback E2E")
	}
	if !config.IsLoggedIn() {
		t.Skip("mount E2E: not logged in — run 'pc li' first")
	}
	if !agent.IsRunning() {
		t.Skip("mount E2E: keys locked — run 'pc uk' first")
	}

	noop := func() {}
	pub, priv := e2ee.GetKeyPair(noop)
	nameKey := e2ee.GetNameKey(noop)
	signPub, signPriv := e2ee.GetSigningKeysIfAvailable(noop)
	if pub == nil || priv == nil || nameKey == nil {
		t.Skip("mount E2E: encryption keys unavailable from the agent")
	}
	if signPub == nil || signPriv == nil {
		t.Skip("mount E2E: signing keys unavailable — uploads require them")
	}

	ctx := context.Background()
	client := api.NewClient()

	testRoot := fmt.Sprintf("mount-e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		opts := map[string]string{"source": "/" + testRoot}
		addPathTokens(opts, testRoot, nameKey)
		client.Execute(context.Background(), "rm", opts)
	})

	dir := t.TempDir()
	cacheDB, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	defer cacheDB.Close()
	store, err := cache.NewStore(dir)
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	evictor := cache.NewEvictor(cacheDB, store, 1<<30)
	v := vfs.New(testRoot, cacheDB, store, evictor, client, pub, priv, nameKey, signPub, signPriv)
	wb := NewWritebackProcessor(v, client, cacheDB, store, dir)

	dirID, err := cacheDB.UpsertInode(&cache.Inode{
		RemotePath:  testRoot,
		DisplayName: testRoot,
		IsDir:       true,
		SyncStatus:  cache.StatusPending,
	})
	if err != nil {
		t.Fatalf("upsert dir inode: %v", err)
	}
	if err := cacheDB.EnqueueWriteback(dirID, "mkdir", testRoot, ""); err != nil {
		t.Fatalf("enqueue mkdir: %v", err)
	}
	if _, err := wb.FlushAll(30 * time.Second); err != nil {
		t.Fatalf("flush mkdir: %v", err)
	}
	if !remoteExists(ctx, client, nameKey, testRoot, "ls") {
		t.Fatalf("mkdir never reached the server: /%s not found", testRoot)
	}

	content := []byte("pigcloud mount writeback e2e probe " + testRoot)
	hash, err := store.Put(content)
	if err != nil {
		t.Fatalf("store put: %v", err)
	}
	filePath := testRoot + "/probe.txt"
	fileID, err := cacheDB.UpsertInode(&cache.Inode{
		RemotePath:  filePath,
		DisplayName: "probe.txt",
		Size:        int64(len(content)),
		Cached:      true,
		ContentHash: hash,
		ParentID:    dirID,
		SyncStatus:  cache.StatusPending,
	})
	if err != nil {
		t.Fatalf("upsert file inode: %v", err)
	}
	if err := cacheDB.EnqueueWriteback(fileID, "upload", filePath, ""); err != nil {
		t.Fatalf("enqueue upload: %v", err)
	}
	if _, err := wb.FlushAll(30 * time.Second); err != nil {
		t.Fatalf("flush upload: %v", err)
	}

	got, err := cacheDB.GetInode(fileID)
	if err != nil {
		t.Fatalf("get inode: %v", err)
	}
	if got.SyncStatus != cache.StatusSynced {
		t.Fatalf("upload not synced: status=%s reason=%q", got.SyncStatus, got.StatusReason)
	}
	if !remoteExists(ctx, client, nameKey, filePath, "in") {
		t.Fatalf("upload marked synced but /%s is not on the server (silent-loss regression)", filePath)
	}
}

func remoteExists(ctx context.Context, client *api.Client, nameKey []byte, path, action string) bool {
	opts := map[string]string{"source": "/" + path}
	addPathTokens(opts, path, nameKey)
	resp, err := client.Execute(ctx, action, opts)
	return err == nil && resp != nil && resp.Success
}
