package syncer

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount/cache"
	"pigcloud/internal/mount/vfs"
)

type identityServer struct {
	mu      sync.Mutex
	uploads []map[string]string
	mks     []map[string]string
	rms     int
	ulReply func(opts map[string]string, n int) (int, string)
}

func (s *identityServer) handle(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("action") == "tee-attestation" {
			io.WriteString(w, `{"success":true,"enabled":false,"available":false}`)
			return
		}
		var command api.CLIRequest
		if meta := r.Header.Get(api.HeaderCliMetadata); meta != "" {
			raw, _ := base64.StdEncoding.DecodeString(meta)
			_ = json.Unmarshal(raw, &command)
			io.Copy(io.Discard, r.Body)
		} else {
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &command)
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		switch command.Command {
		case "ul":
			s.uploads = append(s.uploads, command.Options)
			status, body := http.StatusOK, `{"success":true,"node_id":"`+command.Options["e2ee_node_id"]+`"}`
			if s.ulReply != nil {
				status, body = s.ulReply(command.Options, len(s.uploads))
			}
			w.WriteHeader(status)
			io.WriteString(w, body)
		case "mk":
			s.mks = append(s.mks, command.Options)
			io.WriteString(w, `{"success":true}`)
		case "rm":
			s.rms++
			io.WriteString(w, `{"success":true}`)
		case "in":
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"success":false,"message":"not found"}`)
		default:
			t.Errorf("unexpected request %q", command.Command)
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"success":false}`)
		}
	}
}

type identityFixture struct {
	writer *WritebackProcessor
	db     *cache.DB
	tree   *vfs.VFS
	local  string
	server *identityServer
}

func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	pub, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := &identityServer{}
	ts := httptest.NewServer(server.handle(t))
	t.Cleanup(ts.Close)
	cfg := config.Get()
	oldEndpoint, oldKey := cfg.Endpoint, cfg.APIKey
	t.Cleanup(func() { cfg.Endpoint, cfg.APIKey = oldEndpoint, oldKey })
	cfg.Endpoint, cfg.APIKey = ts.URL, "test"
	client := api.NewClient()
	local := t.TempDir()
	db, err := cache.Open(filepath.Join(local, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tree := vfs.New("", db, nil, nil, client, pub, priv, nameKey, signPub, signPriv)
	return &identityFixture{writer: NewWritebackProcessor(tree, client, db, nil, local), db: db, tree: tree, local: local, server: server}
}

func (f *identityFixture) localFile(t *testing.T, remotePath, content string) int64 {
	t.Helper()
	full := filepath.Join(f.local, filepath.FromSlash(remotePath))
	if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, full, content)
	id, err := f.db.UpsertInode(&cache.Inode{RemotePath: remotePath, DisplayName: filepath.Base(full), Size: int64(len(content)), Dirty: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (f *identityFixture) claimOne(t *testing.T) *cache.WritebackEntry {
	t.Helper()
	entries, err := f.db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("queue holds %d claimable rows (%v), want 1", len(entries), err)
	}
	return entries[0]
}

func openWireRef(t *testing.T, nodeID, sealed string, parentKey []byte) string {
	t.Helper()
	blob, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := hex.DecodeString(nodeID)
	parent, err := crypto.OpenParentRef(blob, id, parentKey, nil)
	if err != nil {
		t.Fatalf("ref does not open under %s: %v", nodeID, err)
	}
	return hex.EncodeToString(parent)
}

func TestARequeuedUploadKeepsItsMintedIdentity(t *testing.T) {
	f := newIdentityFixture(t)
	const docsID = "d0c5d0c5d0c5d0c5d0c5d0c5d0c5d0c5"
	if _, err := f.db.UpsertInode(&cache.Inode{RemotePath: "Docs", DisplayName: "Docs", IsDir: true, NodeID: docsID, SyncStatus: cache.StatusSynced}); err != nil {
		t.Fatal(err)
	}
	id := f.localFile(t, "Docs/a.txt", "AAA")

	f.db.EnqueueWriteback(id, "upload", "Docs/a.txt", "")
	f.db.EnqueueWriteback(id, "upload", "Docs/a.txt", "")
	first := f.claimOne(t)
	minted := cache.ParseWritebackExtra(first.ExtraJSON)
	if minted.NodeID == "" || minted.SealedParent == "" || minted.ParentID != docsID {
		t.Fatalf("enqueue minted no identity sealed to the known folder: %+v", minted)
	}

	f.db.DeleteWriteback(first.ID)
	if err := f.db.EnqueueWriteback(id, "upload", "Docs/a.txt", ""); err != nil {
		t.Fatal(err)
	}
	requeued := f.claimOne(t)
	if again := cache.ParseWritebackExtra(requeued.ExtraJSON); again.NodeID != minted.NodeID {
		t.Fatalf("requeue minted %s, the first enqueue %s", again.NodeID, minted.NodeID)
	}

	if !f.writer.processEntry(context.Background(), requeued) {
		t.Fatal("upload failed")
	}
	if len(f.server.uploads) != 1 || f.server.uploads[0]["e2ee_node_id"] != minted.NodeID {
		t.Fatalf("uploads %v, want one carrying %s", f.server.uploads, minted.NodeID)
	}
	if got := openWireRef(t, minted.NodeID, f.server.uploads[0]["e2ee_sealed_parent"], f.tree.ParentKey); got != docsID {
		t.Errorf("sent ref opens to %s, want the folder %s", got, docsID)
	}
	inode, _ := f.db.GetInode(id)
	if inode.NodeID != minted.NodeID || inode.PendingNodeID != "" {
		t.Errorf("after the receipt the inode holds confirmed %q pending %q, want %q confirmed", inode.NodeID, inode.PendingNodeID, minted.NodeID)
	}
}

func TestARecreatedFileNeverReusesTheDeletedNodesID(t *testing.T) {
	f := newIdentityFixture(t)
	const oldID = "01d01d01d01d01d01d01d01d01d01d01"
	id := f.localFile(t, "a.txt", "AAA")
	f.db.SetInodeNodeID(id, oldID)
	if err := os.Remove(filepath.Join(f.local, "a.txt")); err != nil {
		t.Fatal(err)
	}

	if err := f.db.EnqueueWriteback(id, "delete", "a.txt", ""); err != nil {
		t.Fatal(err)
	}
	if !f.writer.processEntry(context.Background(), f.claimOne(t)) || f.server.rms != 1 {
		t.Fatal("delete did not go through")
	}
	if inode, _ := f.db.GetInode(id); inode != nil && (inode.NodeID != "" || inode.PendingNodeID != "") {
		t.Fatalf("a completed delete kept the doomed id: %+v", inode)
	}

	recreated := f.localFile(t, "a.txt", "BBB")
	f.db.EnqueueWriteback(recreated, "upload", "a.txt", "")
	entry := f.claimOne(t)
	if x := cache.ParseWritebackExtra(entry.ExtraJSON); x.NodeID == "" || x.NodeID == oldID {
		t.Fatalf("the recreated file carries %q, the trashed node's id is %q", x.NodeID, oldID)
	}
}

func TestAChildWaitsForItsParentsQueuedMkdir(t *testing.T) {
	f := newIdentityFixture(t)
	dirID, err := f.db.UpsertInode(&cache.Inode{RemotePath: "New", DisplayName: "New", IsDir: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	f.db.EnqueueWriteback(dirID, "mkdir", "New", "")
	child := f.localFile(t, "New/f.txt", "CCC")
	f.db.EnqueueWriteback(child, "upload", "New/f.txt", "")

	entries, err := f.db.DequeueWriteback(10, 0)
	if err != nil || len(entries) != 2 {
		t.Fatalf("queue: %d %v", len(entries), err)
	}
	mkdir, upload := entries[0], entries[1]
	if upload.Action != "upload" {
		mkdir, upload = upload, mkdir
	}
	if x := cache.ParseWritebackExtra(upload.ExtraJSON); x.SealedParent != "" {
		t.Fatalf("a child was sealed to its parent's unconfirmed id at enqueue: %+v", x)
	}

	if f.writer.processEntry(context.Background(), upload) {
		t.Fatal("the child went out before its parent existed")
	}
	if len(f.server.uploads) != 0 {
		t.Fatalf("uploads sent: %v", f.server.uploads)
	}
	if waiting, _, err := f.db.DeferredWritebackCount(time.Now().Unix() + 1); err != nil || waiting != 1 {
		t.Fatalf("the waiting child is not parked pending: %d %v", waiting, err)
	}
	if failed, _ := f.db.FailedWritebackCount(); failed != 0 {
		t.Fatal("waiting on a parent counted as a failure")
	}

	if !f.writer.processEntry(context.Background(), mkdir) {
		t.Fatal("mkdir failed")
	}
	dir, _ := f.db.GetInode(dirID)
	if dir.NodeID == "" || dir.NodeID != f.server.mks[0]["e2ee_node_id"] {
		t.Fatalf("mkdir did not confirm the folder's id: %+v", dir)
	}

	upload.Attempts = 0
	if !f.writer.processEntry(context.Background(), upload) {
		t.Fatal("child upload failed after its parent was created")
	}
	sent := f.server.uploads[0]
	if got := openWireRef(t, sent["e2ee_node_id"], sent["e2ee_sealed_parent"], f.tree.ParentKey); got != dir.NodeID {
		t.Errorf("child sealed to %s, want its parent %s", got, dir.NodeID)
	}
}

func TestAChildFailsWhenItsParentsMkdirFailedPermanently(t *testing.T) {
	f := newIdentityFixture(t)
	dirID, err := f.db.UpsertInode(&cache.Inode{RemotePath: "New", DisplayName: "New", IsDir: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	f.db.EnqueueWriteback(dirID, "mkdir", "New", "")
	child := f.localFile(t, "New/f.txt", "CCC")
	f.db.EnqueueWriteback(child, "upload", "New/f.txt", "")
	entries, _ := f.db.DequeueWriteback(10, 0)
	var upload *cache.WritebackEntry
	for _, e := range entries {
		if e.Action == "mkdir" {
			f.db.UpdateWriteback(e.ID, "failed", "refused", maxRetries)
		} else {
			upload = e
		}
	}
	if f.writer.processEntry(context.Background(), upload) {
		t.Fatal("a child of a folder that was never created went out")
	}
	if len(f.server.uploads) != 0 {
		t.Fatalf("uploads sent: %v", f.server.uploads)
	}
	if inode, _ := f.db.GetInode(child); inode.SyncStatus != cache.StatusFailed {
		t.Errorf("the child is %q, want failed once its parent's mkdir failed", inode.SyncStatus)
	}
}

func TestATakenIDIsRemintedOnceThenTheItemFails(t *testing.T) {
	f := newIdentityFixture(t)
	taken := `{"success":false,"errorCode":"node_id_taken","message":"node id already in use"}`
	f.server.ulReply = func(opts map[string]string, n int) (int, string) {
		if n == 1 {
			return http.StatusConflict, taken
		}
		return http.StatusOK, `{"success":true,"node_id":"` + opts["e2ee_node_id"] + `"}`
	}
	id := f.localFile(t, "a.txt", "AAA")
	f.db.EnqueueWriteback(id, "upload", "a.txt", "")
	if !f.writer.processEntry(context.Background(), f.claimOne(t)) {
		t.Fatal("upload failed after one re-mint")
	}
	if len(f.server.uploads) != 2 || f.server.uploads[0]["e2ee_node_id"] == f.server.uploads[1]["e2ee_node_id"] {
		t.Fatalf("uploads %v, want a second one under a fresh id", f.server.uploads)
	}
	if inode, _ := f.db.GetInode(id); inode.NodeID != f.server.uploads[1]["e2ee_node_id"] {
		t.Errorf("inode confirmed %q, want the re-minted %q", inode.NodeID, f.server.uploads[1]["e2ee_node_id"])
	}

	f.server.ulReply = func(map[string]string, int) (int, string) { return http.StatusConflict, taken }
	again := f.localFile(t, "b.txt", "BBB")
	f.db.EnqueueWriteback(again, "upload", "b.txt", "")
	if f.writer.processEntry(context.Background(), f.claimOne(t)) {
		t.Fatal("a twice-taken id reported success")
	}
	if inode, _ := f.db.GetInode(again); inode.SyncStatus != cache.StatusFailed || inode.StatusReason == "" {
		t.Errorf("the item did not fail with the server's message: %+v", inode)
	}
}

func TestAnUnresolvableParentDefersTheCreate(t *testing.T) {
	_, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body, _ := io.ReadAll(r.Body)
		var command api.CLIRequest
		json.Unmarshal(body, &command)
		if command.Command != "in" {
			t.Errorf("sent %q before the parent resolved", command.Command)
		}
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"success":false,"message":"refused"}`)
	}))
	t.Cleanup(server.Close)
	cfg := config.Get()
	oldEndpoint, oldKey := cfg.Endpoint, cfg.APIKey
	t.Cleanup(func() { cfg.Endpoint, cfg.APIKey = oldEndpoint, oldKey })
	cfg.Endpoint, cfg.APIKey = server.URL, "test"
	client := api.NewClient()

	db, err := cache.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	nameKey, _ := crypto.DeriveNameKey(priv)
	tree := vfs.New("", db, nil, nil, client, nil, priv, nameKey, nil, nil)
	writer := NewWritebackProcessor(tree, client, db, nil, "")

	id, err := db.UpsertInode(&cache.Inode{RemotePath: "Unknown/New", DisplayName: "New", IsDir: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	db.EnqueueWriteback(id, "mkdir", "Unknown/New", "")
	entries, err := db.DequeueWriteback(1, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("queue: %v", err)
	}
	if x := cache.ParseWritebackExtra(entries[0].ExtraJSON); x.NodeID == "" || x.SealedParent != "" {
		t.Fatalf("enqueue with an unknown parent: %+v; want an id and no ref", x)
	}
	if err := writer.processMkdir(context.Background(), entries[0]); err == nil || isPermanent(err) {
		t.Fatalf("mkdir with an unresolved parent: %v; want a transient refusal", err)
	}
}
