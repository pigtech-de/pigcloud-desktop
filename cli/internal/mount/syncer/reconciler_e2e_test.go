package syncer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"pigcloud/internal/agent"
	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func TestReconcilerE2E(t *testing.T) {
	if os.Getenv("PIGCLOUD_MOUNT_E2E") == "" {
		t.Skip("set PIGCLOUD_MOUNT_E2E=1 (with a logged-in, unlocked CLI) to run the reconciler E2E")
	}
	if !config.IsLoggedIn() {
		t.Skip("reconciler E2E: not logged in — run 'pc li' first")
	}
	if !agent.IsRunning() {
		t.Skip("reconciler E2E: keys locked — run 'pc uk' first")
	}

	noop := func() {}
	pub, priv := e2ee.GetKeyPair(noop)
	nameKey := e2ee.GetNameKey(noop)
	signPub, signPriv := e2ee.GetSigningKeysIfAvailable(noop)
	if pub == nil || priv == nil || nameKey == nil || signPub == nil || signPriv == nil {
		t.Skip("reconciler E2E: keys unavailable from the agent")
	}

	ctx := context.Background()
	client := api.NewClient()

	testRoot := fmt.Sprintf("mount-recon-e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		opts := map[string]string{"source": "/" + testRoot}
		addPathTokens(opts, testRoot, nameKey)
		client.Execute(context.Background(), "rm", opts)
	})

	syncDir := t.TempDir()
	cacheDB, err := cache.Open(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	defer cacheDB.Close()
	store, err := cache.NewStore(filepath.Join(syncDir, ".pigcloud"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	defer store.Close()

	evictor := cache.NewEvictor(cacheDB, store, 1<<30)
	v := vfs.New(testRoot, cacheDB, store, evictor, client, pub, priv, nameKey, signPub, signPriv)
	wb := NewWritebackProcessor(v, client, cacheDB, store, syncDir)

	dirID, err := cacheDB.UpsertInode(&cache.Inode{
		RemotePath:  testRoot,
		DisplayName: testRoot,
		IsDir:       true,
		SyncStatus:  cache.StatusPending,
	})
	if err != nil {
		t.Fatalf("upsert dir inode: %v", err)
	}
	cacheDB.EnqueueWriteback(dirID, "mkdir", testRoot, "")
	if _, err := wb.FlushAll(30 * time.Second); err != nil {
		t.Fatalf("flush mkdir: %v", err)
	}

	if err := os.WriteFile(filepath.Join(syncDir, "dropped.txt"), []byte("dropped past the watcher"), 0600); err != nil {
		t.Fatalf("write dropped file: %v", err)
	}

	r := NewReconciler(syncDir, testRoot, cacheDB, time.Minute)
	if healed := r.Reconcile(ctx); healed != 1 {
		t.Fatalf("reconcile healed=%d, want 1", healed)
	}
	if _, err := wb.FlushAll(30 * time.Second); err != nil {
		t.Fatalf("flush upload: %v", err)
	}

	if !remoteExists(ctx, client, nameKey, testRoot+"/dropped.txt", "in") {
		t.Fatalf("reconciler-queued upload never reached the server")
	}
}
