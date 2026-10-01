package syncer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

func pollFixture(t *testing.T) (p *Poller, db *cache.DB, v *vfs.VFS, pub *crypto.PublicKeySet, setLS func(entries ...remoteEntry)) {
	t.Helper()

	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("name key: %v", err)
	}

	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)

	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "test"
	client := api.NewClient()

	v = vfs.New("", db, nil, nil, client, pub, priv, nameKey, nil, nil)
	v.Root.Loaded = true

	p = NewPoller(v, client, db, time.Minute)

	setLS = func(entries ...remoteEntry) {
		body = lsJSON(t, pub, entries)
	}
	return p, db, v, pub, setLS
}

type remoteEntry struct {
	name      string
	isDir     bool
	size      int64
	haveSize  bool
	modified  time.Time
	haveMtime bool
	etag      string
}

func sealedName(t *testing.T, pub *crypto.PublicKeySet, name string) string {
	t.Helper()
	sealed, err := crypto.SealDisplayName(name, pub)
	if err != nil {
		t.Fatalf("seal %q: %v", name, err)
	}
	return base64.StdEncoding.EncodeToString(sealed)
}

func lsJSON(t *testing.T, pub *crypto.PublicKeySet, entries []remoteEntry) string {
	t.Helper()
	out := make([]api.ListEntry, 0, len(entries))
	for _, e := range entries {
		le := api.ListEntry{Type: "file", E2EEDisplayName: sealedName(t, pub, e.name), ETag: e.etag}
		if e.isDir {
			le.Type = "directory"
		}
		if e.haveSize {
			s := e.size
			le.PlaintextSize = &s
		}
		if e.haveMtime {
			m := e.modified.UTC().Format(time.RFC3339)
			le.Modified = &m
		}
		out = append(out, le)
	}
	b, err := json.Marshal(map[string]any{"success": true, "entries": out})
	if err != nil {
		t.Fatalf("marshal ls: %v", err)
	}
	return string(b)
}

func addExistingFile(t *testing.T, p *Poller, db *cache.DB, name string, size int64, mtime time.Time, nodeDirty, dbDirty bool) *vfs.Node {
	t.Helper()
	node := vfs.NewFileNode(name, name, size, mtime, p.vfs.Root)
	node.Cached = true
	node.ContentHash = "h-" + name
	node.SyncStatus = cache.StatusSynced
	node.Dirty = nodeDirty
	id, err := db.UpsertInode(&cache.Inode{
		RemotePath:  name,
		DisplayName: name,
		Size:        size,
		Mtime:       mtime.Unix(),
		Cached:      true,
		Dirty:       dbDirty,
		ContentHash: "h-" + name,
		SyncStatus:  cache.StatusSynced,
	})
	if err != nil {
		t.Fatalf("upsert %q: %v", name, err)
	}
	node.ID = id
	p.vfs.Root.AddChild(node)
	return node
}

func TestPollerConflictMatrix(t *testing.T) {
	base := time.Now().Add(-2 * time.Hour).Truncate(time.Second).UTC()
	newer := base.Add(time.Hour)

	type outcome int
	const (
		conflict outcome = iota
		download
		noop
	)

	cases := []struct {
		name      string
		nodeDirty bool
		dbDirty   bool
		entrySize int64
		haveSize  bool
		entryTime time.Time
		haveMtime bool
		want      outcome
	}{
		{"dirty_node_size_grew", true, false, 200, true, time.Time{}, false, conflict},
		{"dirty_node_mtime_advanced", true, false, 100, true, newer, true, conflict},
		{"dirty_via_db_only_size_grew", false, true, 200, true, time.Time{}, false, conflict},
		{"clean_size_grew", false, false, 200, true, time.Time{}, false, download},
		{"clean_mtime_advanced", false, false, 100, true, newer, true, download},
		{"clean_same_size_no_mtime", false, false, 100, true, time.Time{}, false, noop},
		{"dirty_same_size_no_change", true, false, 100, true, time.Time{}, false, noop},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, db, _, _, setLS := pollFixture(t)
			node := addExistingFile(t, p, db, "f.txt", 100, base, c.nodeDirty, c.dbDirty)

			db.RecordSyncFailure(&cache.SyncFailure{
				InodeID: node.ID, Kind: cache.FailureDownload, Attempts: 1,
				NextRetryAt: time.Now().Add(time.Hour).Unix(),
			})

			setLS(remoteEntry{name: "f.txt", haveSize: c.haveSize, size: c.entrySize, haveMtime: c.haveMtime, modified: c.entryTime})
			if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
				t.Fatalf("pollRecursive: %v", err)
			}

			dbInode, _ := db.GetInode(node.ID)
			switch c.want {
			case conflict:
				if node.SyncStatus != cache.StatusConflict {
					t.Errorf("node status = %q, want conflict", node.SyncStatus)
				}
				if dbInode.SyncStatus != cache.StatusConflict {
					t.Errorf("db status = %q, want conflict", dbInode.SyncStatus)
				}
				if !node.Mtime.Equal(base) {
					t.Errorf("conflict advanced mtime to %v, want %v (held stale)", node.Mtime, base)
				}
				if node.Size != 100 || !node.Cached {
					t.Errorf("conflict mutated content state: size=%d cached=%v", node.Size, node.Cached)
				}
			case download:
				if node.SyncStatus == cache.StatusConflict {
					t.Error("clean remote change wrongly flagged conflict")
				}
				if node.Cached {
					t.Error("download branch left node cached")
				}
				if node.ContentHash != "" {
					t.Errorf("download branch kept content hash %q", node.ContentHash)
				}
				if node.Size != c.entrySize {
					t.Errorf("size = %d, want %d", node.Size, c.entrySize)
				}
				if dbInode.Cached {
					t.Error("db cache not invalidated")
				}
				if f, _ := db.GetSyncFailure(node.ID, cache.FailureDownload); f != nil {
					t.Error("download failure not cleared for re-fetch")
				}
			case noop:
				if node.SyncStatus == cache.StatusConflict {
					t.Error("no-op change wrongly flagged conflict")
				}
				if !node.Cached || node.ContentHash == "" {
					t.Errorf("no-op change invalidated cache: cached=%v hash=%q", node.Cached, node.ContentHash)
				}
				if node.Size != 100 {
					t.Errorf("no-op change resized node to %d", node.Size)
				}
			}
		})
	}
}

func TestPollerCreatesNewRemoteFile(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	mtime := time.Now().Add(-time.Minute).Truncate(time.Second).UTC()

	setLS(remoteEntry{name: "fresh.txt", haveSize: true, size: 42, haveMtime: true, modified: mtime})
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("pollRecursive: %v", err)
	}

	child := p.vfs.Root.GetChild("fresh.txt")
	if child == nil {
		t.Fatal("new remote file not added to the tree")
	}
	if child.IsDir || child.Size != 42 {
		t.Errorf("new file node wrong: isDir=%v size=%d", child.IsDir, child.Size)
	}
	in, _ := db.GetInodeByPath("fresh.txt")
	if in == nil || in.SyncStatus != cache.StatusSynced {
		t.Errorf("new file not tracked as synced inode: %+v", in)
	}
}

func TestPollerPrunesCleanRemoteDeletion(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	node := addExistingFile(t, p, db, "gone.txt", 10, time.Now(), false, false)
	node.ContentHash = ""

	var deleted []string
	p.SetLocalDelete(func(remotePath string) { deleted = append(deleted, remotePath) })

	setLS()
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("pollRecursive: %v", err)
	}

	if p.vfs.Root.GetChild("gone.txt") != nil {
		t.Error("pruned file still in the tree")
	}
	if len(deleted) != 1 || deleted[0] != "gone.txt" {
		t.Errorf("local delete callback = %v, want [gone.txt]", deleted)
	}
	if in, _ := db.GetInodeByPath("gone.txt"); in != nil {
		t.Error("pruned inode still in the cache DB")
	}
}

func TestPollerKeepsDirtyNodeOnRemoteDeletion(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	addExistingFile(t, p, db, "edited.txt", 10, time.Now(), true , false)

	var deleted []string
	p.SetLocalDelete(func(remotePath string) { deleted = append(deleted, remotePath) })

	setLS()
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("pollRecursive: %v", err)
	}

	if p.vfs.Root.GetChild("edited.txt") == nil {
		t.Error("dirty file was pruned on remote deletion")
	}
	if len(deleted) != 0 {
		t.Errorf("local delete fired for a dirty file: %v", deleted)
	}
	if in, _ := db.GetInodeByPath("edited.txt"); in == nil {
		t.Error("dirty inode dropped from the cache DB")
	}
}

func TestPollerKeepsDbDirtyNodeOnRemoteDeletion(t *testing.T) {
	p, db, _, _, setLS := pollFixture(t)
	node := addExistingFile(t, p, db, "dbedit.txt", 10, time.Now(), false , true )
	node.ContentHash = ""

	var deleted []string
	p.SetLocalDelete(func(remotePath string) { deleted = append(deleted, remotePath) })

	setLS()
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("pollRecursive: %v", err)
	}

	if p.vfs.Root.GetChild("dbedit.txt") == nil {
		t.Error("db-dirty file was pruned on remote deletion (REL-CLT-13 regressed)")
	}
	if len(deleted) != 0 {
		t.Errorf("local delete fired for a db-dirty file: %v", deleted)
	}
	if in, _ := db.GetInodeByPath("dbedit.txt"); in == nil {
		t.Error("db-dirty inode dropped from the cache DB")
	}
}

func TestPollerTracksDiscoveredNodesInTheIDMap(t *testing.T) {
	p, _, v, _, setLS := pollFixture(t)

	setLS(remoteEntry{name: "appeared.txt", haveSize: true, size: 7})
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("pollRecursive: %v", err)
	}

	child := p.vfs.Root.GetChild("appeared.txt")
	if child == nil {
		t.Fatal("new remote file not added to the tree")
	}
	if child.ID == 0 {
		t.Fatal("new remote file got no cache inode id")
	}
	if got := v.NodeByID(child.ID); got != child {
		t.Errorf("NodeByID(%d) = %v, want the discovered node: eviction and conflict hooks no-op for it", child.ID, got)
	}

	setLS()
	if err := p.pollRecursive(context.Background(), p.vfs.Root); err != nil {
		t.Fatalf("second pollRecursive: %v", err)
	}
	if p.vfs.Root.GetChild("appeared.txt") != nil {
		t.Fatal("pruned file still in the tree")
	}
	if got := v.NodeByID(child.ID); got != nil {
		t.Errorf("NodeByID(%d) = %v after the prune, want nil", child.ID, got)
	}
}
