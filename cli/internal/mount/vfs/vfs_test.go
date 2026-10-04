package vfs

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
	"pigcloud/internal/mount/cache"
)

var (
	keysOnce  sync.Once
	tPub      *crypto.PublicKeySet
	tPriv     *crypto.PrivateKeySet
	tNameKey  []byte
	tSignPub  *crypto.SigningPublicKeySet
	tSignPriv *crypto.SigningPrivateKeySet
	keysErr   error
)

func testKeys(t *testing.T) {
	t.Helper()
	keysOnce.Do(func() {
		tPub, tPriv, keysErr = crypto.GenerateHybridKeyPair()
		if keysErr != nil {
			return
		}
		tNameKey, keysErr = crypto.DeriveNameKey(tPriv)
		if keysErr != nil {
			return
		}
		tSignPub, tSignPriv, keysErr = crypto.GenerateSigningKeyPair()
	})
	if keysErr != nil {
		t.Fatalf("test keygen: %v", keysErr)
	}
}

type cliCall struct {
	Command string            `json:"command"`
	Options map[string]string `json:"options"`
}

type fakeServer struct {
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	calls    []cliCall
	srv      *httptest.Server
}

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{handlers: map[string]http.HandlerFunc{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var call cliCall
		json.Unmarshal(body, &call)
		f.mu.Lock()
		f.calls = append(f.calls, call)
		h := f.handlers[call.Command]
		f.mu.Unlock()
		if h == nil {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"success":false,"message":"no test handler for %s"}`, call.Command)
			return
		}
		h(w, r)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeServer) handle(command string, h http.HandlerFunc) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[command] = h
}

func (f *fakeServer) handleJSON(command, body string) {
	f.handle(command, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, body)
	})
}

func (f *fakeServer) callsFor(command string) []cliCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []cliCall
	for _, c := range f.calls {
		if c.Command == command {
			out = append(out, c)
		}
	}
	return out
}

type vfsEnv struct {
	fs  *VFS
	srv *fakeServer
	db  *cache.DB
}

func newVFSEnv(t *testing.T, remoteBase string) *vfsEnv {
	t.Helper()
	testKeys(t)
	srv := newFakeServer(t)

	cfgDir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", cfgDir)
	t.Setenv("APPDATA", cfgDir)
	origCfg := config.GetConfigPath()
	config.SetConfigFile(filepath.Join(cfgDir, "pigcloud", "config.json"))
	config.Load()
	cfg := config.Get()
	cfg.Endpoint = srv.srv.URL
	cfg.APIKey = "vfs-test-key"
	t.Cleanup(func() {
		config.SetConfigFile(origCfg)
		config.Load()
	})

	cacheDir := t.TempDir()
	db, err := cache.Open(cacheDir)
	if err != nil {
		t.Fatalf("cache open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := cache.NewStore(cacheDir)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(store.Close)
	evictor := cache.NewEvictor(db, store, 1<<40)

	fs := New(remoteBase, db, store, evictor, api.NewClient(), tPub, tPriv, tNameKey, tSignPub, tSignPriv)
	return &vfsEnv{fs: fs, srv: srv, db: db}
}

func sealName(t *testing.T, name string) string {
	t.Helper()
	sealed, err := crypto.SealDisplayName(name, tPub)
	if err != nil {
		t.Fatalf("seal name: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sealed)
}

func lsBody(t *testing.T, entries []api.ListEntry) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"success": true,
		"path":    "/",
		"entries": entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func i64(v int64) *int64   { return &v }
func str(v string) *string { return &v }

func TestNewNormalizesRemoteBase(t *testing.T) {
	env := newVFSEnv(t, "/")
	if env.fs.RemoteBase != "" {
		t.Errorf("base %q, want empty for /", env.fs.RemoteBase)
	}
	env2 := newVFSEnv(t, "/Photos")
	if env2.fs.RemoteBase != "Photos" {
		t.Errorf("base %q, want Photos", env2.fs.RemoteBase)
	}
}

func TestReadOnlyRejectsAllMutations(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.SetReadOnly(true)
	root := env.fs.Root
	file := NewFileNode("f.txt", "f.txt", 0, time.Now(), root)
	root.AddChild(file)

	if _, err := env.fs.Create(root, "x.txt"); err != ErrReadOnly {
		t.Errorf("Create: %v", err)
	}
	if _, err := env.fs.Mkdir(root, "d"); err != ErrReadOnly {
		t.Errorf("Mkdir: %v", err)
	}
	if _, err := env.fs.Write(file, 0, []byte("x")); err != ErrReadOnly {
		t.Errorf("Write: %v", err)
	}
	if err := env.fs.Truncate(file, 0); err != ErrReadOnly {
		t.Errorf("Truncate: %v", err)
	}
	if err := env.fs.Unlink(root, "f.txt"); err != ErrReadOnly {
		t.Errorf("Unlink: %v", err)
	}
	if err := env.fs.Rmdir(root, "f.txt"); err != ErrReadOnly {
		t.Errorf("Rmdir: %v", err)
	}
	if err := env.fs.Rename(root, "f.txt", root, "g.txt"); err != ErrReadOnly {
		t.Errorf("Rename: %v", err)
	}
	if len(env.srv.calls) != 0 {
		t.Errorf("read-only mode reached the server: %v", env.srv.calls)
	}
}

func TestPopulateDirDecryptsAndFilters(t *testing.T) {
	env := newVFSEnv(t, "")
	mod := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC).Format(time.RFC3339)
	env.srv.handleJSON("ls", lsBody(t, []api.ListEntry{
		{Type: "file", Size: i64(9999), PlaintextSize: i64(1234), Modified: str(mod), E2EEDisplayName: sealName(t, "report.pdf")},
		{Type: "directory", E2EEDisplayName: sealName(t, "Fotos")},
		{Type: "directory", E2EEDisplayName: sealName(t, ".Trash")},
		{Type: "file", E2EEDisplayName: "!!garbage!!"},
		{Type: "file", E2EEDisplayName: sealName(t, "../escape")},
	}))

	children, err := env.fs.Readdir(env.fs.Root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	byName := map[string]*Node{}
	for _, c := range children {
		byName[c.Name] = c
	}
	if len(byName) != 2 {
		t.Errorf("children = %v (excluded/undecryptable/unsafe must be filtered)", byName)
	}
	f := byName["report.pdf"]
	if f == nil || f.IsDir {
		t.Fatalf("report.pdf missing: %v", byName)
	}
	if f.Size != 1234 {
		t.Errorf("size = %d, want plaintext_size 1234 (never ciphertext size)", f.Size)
	}
	if f.Mtime.UTC().Format(time.RFC3339) != mod {
		t.Errorf("mtime = %v", f.Mtime)
	}
	if f.RemotePath != "report.pdf" || f.ID == 0 {
		t.Errorf("node not persisted: %+v", f)
	}
	d := byName["Fotos"]
	if d == nil || !d.IsDir {
		t.Errorf("Fotos dir missing: %v", byName)
	}
	if env.fs.NodeByID(f.ID) != f {
		t.Error("node not tracked by ID")
	}

	if _, err := env.fs.Readdir(env.fs.Root); err != nil {
		t.Fatal(err)
	}
	if n := len(env.srv.callsFor("ls")); n != 1 {
		t.Errorf("ls called %d times, want 1", n)
	}
}

func TestReaddirPreservesBackfilledSizeForSidecarlessFile(t *testing.T) {
	env := newVFSEnv(t, "")

	if _, err := env.db.UpsertInode(&cache.Inode{
		RemotePath: "legacy.dat", DisplayName: "legacy.dat", Size: 4096,
		Cached: true, SyncStatus: cache.StatusSynced,
	}); err != nil {
		t.Fatal(err)
	}

	env.srv.handleJSON("ls", lsBody(t, []api.ListEntry{
		{Type: "file", Size: i64(5120), E2EEDisplayName: sealName(t, "legacy.dat")},
	}))

	children, err := env.fs.Readdir(env.fs.Root)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	var node *Node
	for _, c := range children {
		if c.Name == "legacy.dat" {
			node = c
		}
	}
	if node == nil {
		t.Fatal("legacy.dat missing from listing")
	}
	if node.Size != 4096 {
		t.Errorf("node size = %d, want 4096 (backfilled size preserved, never reset to 0)", node.Size)
	}
	in, _ := env.db.GetInodeByPath("legacy.dat")
	if in == nil || in.Size != 4096 {
		t.Errorf("db size = %v, want 4096 (readdir must not clobber the backfill)", in)
	}
}

func TestOpenPersistsPlaintextSize(t *testing.T) {
	env := newVFSEnv(t, "")
	plaintext := []byte("legacy body with no plaintext_size sidecar in the listing")
	ciphertext, metaHeader := e2eeFilePayload(t, plaintext)
	env.srv.handle("dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-CLI-Metadata", metaHeader)
		w.Write(ciphertext)
	})

	root := env.fs.Root
	root.Loaded = true
	node := NewFileNode("legacy.txt", "legacy.txt", int64(len(ciphertext)), time.Now(), root)
	root.AddChild(node)
	id, _ := env.db.UpsertInode(nodeToInode(node, 0))
	node.ID = id
	env.fs.trackNode(node)

	if err := env.fs.Open(node); err != nil {
		t.Fatalf("open: %v", err)
	}
	in, _ := env.db.GetInode(id)
	if in == nil || in.Size != int64(len(plaintext)) {
		t.Errorf("db size = %v, want persisted plaintext len %d", in, len(plaintext))
	}
}

func TestLookup(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handleJSON("ls", lsBody(t, []api.ListEntry{
		{Type: "file", PlaintextSize: i64(5), E2EEDisplayName: sealName(t, "a.txt")},
	}))

	if _, err := env.fs.Lookup(env.fs.Root, ".Trash"); err == nil {
		t.Error("excluded dir resolved")
	}
	n, err := env.fs.Lookup(env.fs.Root, "a.txt")
	if err != nil || n.Name != "a.txt" {
		t.Errorf("lookup: %v %v", n, err)
	}
	if _, err := env.fs.Lookup(env.fs.Root, "missing.txt"); err == nil {
		t.Error("missing child resolved")
	}
}

func TestReaddirOnFileFails(t *testing.T) {
	env := newVFSEnv(t, "")
	f := NewFileNode("x", "x", 0, time.Now(), env.fs.Root)
	if _, err := env.fs.Readdir(f); err == nil {
		t.Error("Readdir on a file succeeded")
	}
}

func TestCreateWriteReadTruncateFlush(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	node, err := env.fs.Create(env.fs.Root, "notes.txt")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !node.Dirty || node.SyncStatus != cache.StatusPending || node.ID == 0 {
		t.Errorf("fresh node: %+v", node)
	}

	if n, err := env.fs.Write(node, 0, []byte("hello")); err != nil || n != 5 {
		t.Fatalf("write: %d %v", n, err)
	}
	if _, err := env.fs.Write(node, 7, []byte("world")); err != nil {
		t.Fatal(err)
	}
	if node.Size != 12 {
		t.Errorf("size = %d, want 12", node.Size)
	}
	got, err := env.fs.Read(node, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := "hello\x00\x00world"; string(got) != want {
		t.Errorf("read = %q, want %q", got, want)
	}
	if b, err := env.fs.Read(node, 50, 10); err != nil || b != nil {
		t.Errorf("read past EOF: %q %v", b, err)
	}
	if b, _ := env.fs.Read(node, 10, 100); string(b) != "ld" {
		t.Errorf("clamped read = %q", b)
	}

	if err := env.fs.Truncate(node, 5); err != nil {
		t.Fatal(err)
	}
	if b, _ := env.fs.Read(node, 0, 100); string(b) != "hello" {
		t.Errorf("after shrink = %q", b)
	}
	if err := env.fs.Truncate(node, 8); err != nil {
		t.Fatal(err)
	}
	if b, _ := env.fs.Read(node, 0, 100); string(b) != "hello\x00\x00\x00" {
		t.Errorf("after grow = %q", b)
	}

	if err := env.fs.Flush(node); err != nil {
		t.Fatal(err)
	}
	if !node.Cached || node.ContentHash == "" {
		t.Errorf("flush did not cache: %+v", node)
	}
	if n, _ := env.db.PendingWritebackCount(); n != 1 {
		t.Errorf("pending writebacks = %d, want 1", n)
	}

	node.Dirty = false
	node.Data = nil
	if b, err := env.fs.Read(node, 1, 3); err != nil || string(b) != "ell" {
		t.Errorf("store read = %q %v", b, err)
	}
}

func TestFlushReleasesSupersededBlob(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	node, err := env.fs.Create(env.fs.Root, "notes.txt")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := env.fs.Write(node, 0, []byte("first version")); err != nil {
		t.Fatal(err)
	}
	if err := env.fs.Flush(node); err != nil {
		t.Fatal(err)
	}
	first := node.ContentHash
	if first == "" {
		t.Fatal("first flush stored nothing")
	}

	if _, err := env.fs.Write(node, 0, []byte("second version, rather longer")); err != nil {
		t.Fatal(err)
	}
	if err := env.fs.Flush(node); err != nil {
		t.Fatal(err)
	}
	if node.ContentHash == first {
		t.Fatal("second flush did not supersede the blob")
	}
	if env.fs.Store.Has(first) {
		t.Errorf("superseded blob %s still on disk after the second flush", first)
	}
	if !env.fs.Store.Has(node.ContentHash) {
		t.Error("current blob was released instead of the superseded one")
	}
}

func TestFlushRejectsUnsyncableFile(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	node, err := env.fs.Create(env.fs.Root, "tool.qqqqqqq")
	if err != nil {
		t.Fatal(err)
	}
	if node.SyncStatus != cache.StatusRejected {
		t.Errorf("unknown extension not rejected at create: %v", node.SyncStatus)
	}
	if _, err := env.fs.Write(node, 0, []byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := env.fs.Flush(node); err != nil {
		t.Fatal(err)
	}
	if node.SyncStatus != cache.StatusRejected || node.StatusReason == "" {
		t.Errorf("flush did not mark rejected: %+v", node)
	}
	if n, _ := env.db.PendingWritebackCount(); n != 0 {
		t.Errorf("rejected file enqueued for upload: %d entries", n)
	}
}

func TestReleaseFlushesLastDirtyHandle(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true
	node, err := env.fs.Create(env.fs.Root, "r.txt")
	if err != nil {
		t.Fatal(err)
	}
	node.OpenCount = 2
	if _, err := env.fs.Write(node, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := env.fs.Release(node); err != nil {
		t.Fatal(err)
	}
	if node.Cached {
		t.Error("flushed while other handles still open")
	}
	if err := env.fs.Release(node); err != nil {
		t.Fatal(err)
	}
	if !node.Cached {
		t.Error("last release did not flush")
	}
}

func TestCreateOverExisting(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	orig, err := env.fs.Create(env.fs.Root, "same.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.fs.Write(orig, 0, []byte("old content")); err != nil {
		t.Fatal(err)
	}
	again, err := env.fs.Create(env.fs.Root, "same.txt")
	if err != nil {
		t.Fatal(err)
	}
	if again != orig {
		t.Error("create over existing minted a new node")
	}
	if again.Size != 0 {
		t.Errorf("existing file not truncated: size %d", again.Size)
	}

	dir := NewDirNode("d", "d", env.fs.Root)
	env.fs.Root.AddChild(dir)
	if _, err := env.fs.Create(env.fs.Root, "d"); err != ErrExists {
		t.Errorf("create over dir: %v", err)
	}
}

func TestMkdirSendsE2EEFields(t *testing.T) {
	env := newVFSEnv(t, "Base")
	env.fs.Root.Loaded = true
	env.srv.handleJSON("mk", `{"success":true}`)

	node, err := env.fs.Mkdir(env.fs.Root, "Neu")
	if err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if !node.IsDir || node.RemotePath != "Base/Neu" || node.ID == 0 {
		t.Errorf("node: %+v", node)
	}
	calls := env.srv.callsFor("mk")
	if len(calls) != 1 {
		t.Fatalf("mk calls = %d", len(calls))
	}
	opts := calls[0].Options
	if opts["source"] != "/Base/Neu" {
		t.Errorf("source = %q", opts["source"])
	}
	sealed, err := base64.StdEncoding.DecodeString(opts["e2ee_display_name"])
	if err != nil {
		t.Fatalf("display name not base64: %v", err)
	}
	name, err := crypto.UnsealDisplayName(sealed, tPriv)
	if err != nil || name != "Neu" {
		t.Errorf("sealed display name = %q (%v)", name, err)
	}
	wantTok, err := crypto.ComputePathToken(tNameKey, "Base/Neu")
	if err != nil {
		t.Fatal(err)
	}
	if opts["e2ee_path_token"] != hex.EncodeToString(wantTok) {
		t.Errorf("path token mismatch")
	}
	var tokens map[string]string
	if json.Unmarshal([]byte(opts["path_tokens"]), &tokens) != nil {
		t.Fatalf("path_tokens not JSON: %q", opts["path_tokens"])
	}
	for _, p := range []string{"Base", "Base/Neu"} {
		tok, _ := crypto.ComputePathToken(tNameKey, p)
		if tokens[p] != hex.EncodeToString(tok) {
			t.Errorf("path_tokens[%q] wrong or missing", p)
		}
	}

	if _, err := env.fs.Mkdir(env.fs.Root, "bad.name"); err == nil {
		t.Error("invalid dir name accepted")
	}
	env.srv.handleJSON("mk", `{"success":false,"message":"quota"}`)
	if _, err := env.fs.Mkdir(env.fs.Root, "Voll"); err == nil || !strings.Contains(err.Error(), "quota") {
		t.Errorf("server rejection: %v", err)
	}
}

func TestUnlinkSyncedCallsServer(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handleJSON("rm", `{"success":true}`)
	root := env.fs.Root
	root.Loaded = true

	file := NewFileNode("gone.txt", "gone.txt", 3, time.Now(), root)
	root.AddChild(file)
	id, err := env.db.UpsertInode(nodeToInode(file, 0))
	if err != nil {
		t.Fatal(err)
	}
	file.ID = id
	env.fs.trackNode(file)

	if err := env.fs.Unlink(root, "gone.txt"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if len(env.srv.callsFor("rm")) != 1 {
		t.Error("rm not sent for a synced file")
	}
	if root.GetChild("gone.txt") != nil {
		t.Error("child still in tree")
	}
	if inode, _ := env.db.GetInodeByPath("gone.txt"); inode != nil {
		t.Error("cache row not deleted")
	}
	if env.fs.NodeByID(id) != nil {
		t.Error("node still tracked")
	}

	if err := env.fs.Unlink(root, "nope"); err != ErrNotFound {
		t.Errorf("missing: %v", err)
	}
	dir := NewDirNode("d", "d", root)
	root.AddChild(dir)
	if err := env.fs.Unlink(root, "d"); err != ErrIsDir {
		t.Errorf("dir: %v", err)
	}
}

func TestUnlinkLocalOnlySkipsServer(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	node, err := env.fs.Create(env.fs.Root, "tmp.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.fs.Write(node, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := env.fs.Flush(node); err != nil {
		t.Fatal(err)
	}
	if n, _ := env.db.PendingWritebackCount(); n != 1 {
		t.Fatalf("precondition: %d pending", n)
	}

	if err := env.fs.Unlink(env.fs.Root, "tmp.txt"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if len(env.srv.callsFor("rm")) != 0 {
		t.Error("rm sent for a never-uploaded file")
	}
	if n, _ := env.db.PendingWritebackCount(); n != 0 {
		t.Errorf("queued upload survived the delete: %d pending", n)
	}
}

func TestRmdir(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handleJSON("rm", `{"success":true}`)
	root := env.fs.Root
	root.Loaded = true

	if err := env.fs.Rmdir(root, "missing"); err != ErrNotFound {
		t.Errorf("missing: %v", err)
	}
	file := NewFileNode("f", "f", 0, time.Now(), root)
	root.AddChild(file)
	if err := env.fs.Rmdir(root, "f"); err == nil {
		t.Error("rmdir on file succeeded")
	}

	full := NewDirNode("full", "full", root)
	full.Loaded = true
	full.AddChild(NewFileNode("kid", "full/kid", 0, time.Now(), full))
	root.AddChild(full)
	if err := env.fs.Rmdir(root, "full"); err != ErrNotEmpty {
		t.Errorf("non-empty: %v", err)
	}

	empty := NewDirNode("empty", "empty", root)
	empty.Loaded = true
	root.AddChild(empty)
	if err := env.fs.Rmdir(root, "empty"); err != nil {
		t.Fatalf("empty rmdir: %v", err)
	}
	if root.GetChild("empty") != nil {
		t.Error("dir still in tree")
	}
	if len(env.srv.callsFor("rm")) != 1 {
		t.Error("rm not sent")
	}

	env.srv.handleJSON("ls", lsBody(t, []api.ListEntry{
		{Type: "file", E2EEDisplayName: sealName(t, "hidden-kid.txt")},
	}))
	unlisted := NewDirNode("unlisted", "unlisted", root)
	root.AddChild(unlisted)
	if err := env.fs.Rmdir(root, "unlisted"); err != ErrNotEmpty {
		t.Errorf("server-side content ignored: %v", err)
	}
}

func TestRenameSyncedFile(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handleJSON("mv", `{"success":true}`)
	root := env.fs.Root
	root.Loaded = true

	file := NewFileNode("old.txt", "old.txt", 3, time.Now(), root)
	root.AddChild(file)
	id, _ := env.db.UpsertInode(nodeToInode(file, 0))
	file.ID = id
	env.fs.trackNode(file)

	if err := env.fs.Rename(root, "old.txt", root, "new.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if root.GetChild("old.txt") != nil || root.GetChild("new.txt") != file {
		t.Error("tree not updated")
	}
	if file.Name != "new.txt" || file.RemotePath != "new.txt" {
		t.Errorf("node not updated: %+v", file)
	}
	if inode, _ := env.db.GetInodeByPath("old.txt"); inode != nil {
		t.Error("old cache row survived")
	}
	if inode, _ := env.db.GetInodeByPath("new.txt"); inode == nil {
		t.Error("new cache row missing")
	}
	calls := env.srv.callsFor("mv")
	if len(calls) != 1 || calls[0].Options["source"] != "/old.txt" || calls[0].Options["target"] != "/new.txt" {
		t.Errorf("mv request: %+v", calls)
	}

	if err := env.fs.Rename(root, "missing", root, "x"); err != ErrNotFound {
		t.Errorf("missing: %v", err)
	}
	if err := env.fs.Rename(root, "new.txt", root, "bad!name.txt"); err != ErrInvalidName {
		t.Errorf("invalid file name: %v", err)
	}
	if err := env.fs.Rename(root, "new.txt", root, "a/b"); err != ErrInvalidName {
		t.Errorf("path separator in name: %v", err)
	}
}

func TestRenameDirRewritesSubtree(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handleJSON("mv", `{"success":true}`)
	root := env.fs.Root
	root.Loaded = true

	dir := NewDirNode("Alt", "Alt", root)
	dir.Loaded = true
	root.AddChild(dir)
	sub := NewDirNode("Sub", "Alt/Sub", dir)
	sub.Loaded = true
	dir.AddChild(sub)
	leaf := NewFileNode("leaf.txt", "Alt/Sub/leaf.txt", 1, time.Now(), sub)
	sub.AddChild(leaf)
	for _, n := range []*Node{dir, sub, leaf} {
		id, _ := env.db.UpsertInode(nodeToInode(n, 0))
		n.ID = id
		env.fs.trackNode(n)
	}

	if err := env.fs.Rename(root, "Alt", root, "Neu"); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	if sub.RemotePath != "Neu/Sub" {
		t.Errorf("sub path = %q", sub.RemotePath)
	}
	if leaf.RemotePath != "Neu/Sub/leaf.txt" {
		t.Errorf("leaf path = %q", leaf.RemotePath)
	}
	if inode, _ := env.db.GetInodeByPath("Neu/Sub/leaf.txt"); inode == nil {
		t.Error("descendant cache row not rewritten")
	}
	if inode, _ := env.db.GetInodeByPath("Alt/Sub/leaf.txt"); inode != nil {
		t.Error("old descendant cache row survived")
	}

	if err := env.fs.Rename(root, "Neu", root, "dot.dot"); err != ErrInvalidName {
		t.Errorf("dir rename with dot: %v", err)
	}
}

func TestRenameLocalOnlyFileSkipsServer(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	node, err := env.fs.Create(env.fs.Root, "draft.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.fs.Write(node, 0, []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := env.fs.Flush(node); err != nil {
		t.Fatal(err)
	}

	if err := env.fs.Rename(env.fs.Root, "draft.txt", env.fs.Root, "final.txt"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if len(env.srv.callsFor("mv")) != 0 {
		t.Error("mv sent for a never-uploaded file")
	}
	if env.fs.Root.GetChild("final.txt") == nil {
		t.Error("renamed node missing")
	}
	if n, _ := env.db.PendingWritebackCount(); n != 1 {
		t.Errorf("pending writebacks = %d, want the re-pointed upload", n)
	}
}

func TestStatfsCachesResult(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handleJSON("st", `{"success":true,"usedBytes":111,"limitBytes":1000}`)

	used, limit, err := env.fs.Statfs()
	if err != nil || used != 111 || limit != 1000 {
		t.Fatalf("statfs: %d %d %v", used, limit, err)
	}
	if _, _, err := env.fs.Statfs(); err != nil {
		t.Fatal(err)
	}
	if n := len(env.srv.callsFor("st")); n != 1 {
		t.Errorf("st called %d times within TTL, want 1", n)
	}

	env2 := newVFSEnv(t, "")
	env2.srv.handleJSON("st", `{"success":false,"message":"denied"}`)
	if _, _, err := env2.fs.Statfs(); err == nil {
		t.Error("server failure not surfaced")
	}
}

func TestCleanRejected(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true

	bad, err := env.fs.Create(env.fs.Root, "virus.qqqqqqq")
	if err != nil {
		t.Fatal(err)
	}
	good, err := env.fs.Create(env.fs.Root, "keep.txt")
	if err != nil {
		t.Fatal(err)
	}
	_ = bad

	count, err := env.fs.CleanRejected()
	if err != nil {
		t.Fatalf("clean: %v", err)
	}
	if count != 1 {
		t.Errorf("removed %d, want 1", count)
	}
	if env.fs.Root.GetChild("virus.qqqqqqq") != nil {
		t.Error("rejected file still in tree")
	}
	if env.fs.Root.GetChild("keep.txt") != good {
		t.Error("healthy file removed")
	}
}

func TestEvictHooks(t *testing.T) {
	env := newVFSEnv(t, "")
	env.fs.Root.Loaded = true
	node, err := env.fs.Create(env.fs.Root, "e.txt")
	if err != nil {
		t.Fatal(err)
	}

	if !env.fs.evictInUse(node.ID) {
		t.Error("dirty node reported evictable")
	}
	node.Dirty = false
	node.OpenCount = 1
	if !env.fs.evictInUse(node.ID) {
		t.Error("open node reported evictable")
	}
	node.OpenCount = 0
	if env.fs.evictInUse(node.ID) {
		t.Error("idle node reported in use")
	}
	if env.fs.evictInUse(999999) {
		t.Error("unknown id reported in use")
	}

	node.Cached = true
	node.ContentHash = "h"
	env.fs.evictClear(node.ID)
	if node.Cached || node.ContentHash != "" {
		t.Error("evictClear left the cached flag")
	}
	env.fs.evictClear(999999)
}

func TestAddPathTokensExpandsAncestors(t *testing.T) {
	env := newVFSEnv(t, "")
	opts := map[string]string{}
	env.fs.AddPathTokensPublic(opts, []string{"a/b/c", ""})

	var tokens map[string]string
	if json.Unmarshal([]byte(opts["path_tokens"]), &tokens) != nil {
		t.Fatalf("path_tokens: %q", opts["path_tokens"])
	}
	if len(tokens) != 3 {
		t.Errorf("token count = %d, want 3 (a, a/b, a/b/c)", len(tokens))
	}
	for _, p := range []string{"a", "a/b", "a/b/c"} {
		want, err := crypto.ComputePathToken(tNameKey, p)
		if err != nil {
			t.Fatal(err)
		}
		if tokens[p] != hex.EncodeToString(want) {
			t.Errorf("token for %q diverges from crypto.ComputePathToken", p)
		}
	}
}

func TestNodeToInodeMapsFields(t *testing.T) {
	mtime := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	n := &Node{
		Name: "x.txt", RemotePath: "d/x.txt", IsDir: false, Size: 7, Mtime: mtime,
		Cached: true, Dirty: true, ContentHash: "hash", SealedKey: "sk", EncMeta: "em",
		Etag: "e1", SyncStatus: cache.StatusConflict, StatusReason: "why",
	}
	in := nodeToInode(n, 42)
	if in.RemotePath != "d/x.txt" || in.DisplayName != "x.txt" || in.IsDir || in.Size != 7 ||
		in.Mtime != mtime.Unix() || !in.Cached || !in.Dirty || in.ContentHash != "hash" ||
		in.SealedKey != "sk" || in.EncMeta != "em" || in.Etag != "e1" || in.ParentID != 42 ||
		in.SyncStatus != cache.StatusConflict || in.StatusReason != "why" {
		t.Errorf("mapping lost a field: %+v", in)
	}
}

func e2eeFilePayload(t *testing.T, plaintext []byte) ([]byte, string) {
	t.Helper()
	dataKey, err := crypto.GenerateDataKey()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	inPath := filepath.Join(dir, "plain")
	outPath := filepath.Join(dir, "cipher")
	if err := os.WriteFile(inPath, plaintext, 0600); err != nil {
		t.Fatal(err)
	}
	meta, err := crypto.EncryptFile(inPath, outPath, dataKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ciphertext, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	sealedKey, err := crypto.SealDataKey(dataKey, tPub)
	if err != nil {
		t.Fatal(err)
	}
	sigEd, sigMl, err := crypto.SignFileBytes(bytes.NewReader(ciphertext), tSignPriv)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		t.Fatal(err)
	}
	payload := api.DownloadPayload{DownloadResult: api.DownloadResult{
		E2EE:             true,
		SealedKey:        base64.StdEncoding.EncodeToString(sealedKey),
		EncryptionMeta:   base64.StdEncoding.EncodeToString(metaJSON),
		SignatureEd25519: base64.StdEncoding.EncodeToString(sigEd),
		SignatureMldsa:   base64.StdEncoding.EncodeToString(sigMl),
		SigningPkEd25519: base64.StdEncoding.EncodeToString(tSignPub.Ed25519[:]),
		SigningPkMldsa:   base64.StdEncoding.EncodeToString(tSignPub.Mldsa),
	}}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext, base64.StdEncoding.EncodeToString(raw)
}

func TestOpenDownloadsDecryptsAndCaches(t *testing.T) {
	env := newVFSEnv(t, "")
	plaintext := []byte("the secret file body, long enough to matter")
	ciphertext, metaHeader := e2eeFilePayload(t, plaintext)
	env.srv.handle("dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-CLI-Metadata", metaHeader)
		w.Write(ciphertext)
	})

	root := env.fs.Root
	root.Loaded = true
	node := NewFileNode("secret.txt", "secret.txt", int64(len(ciphertext)), time.Now(), root)
	root.AddChild(node)
	id, _ := env.db.UpsertInode(nodeToInode(node, 0))
	node.ID = id
	env.fs.trackNode(node)

	if err := env.fs.Open(node); err != nil {
		t.Fatalf("open: %v", err)
	}
	if !node.Cached || node.Size != int64(len(plaintext)) {
		t.Errorf("node after open: cached=%v size=%d", node.Cached, node.Size)
	}
	got, err := env.fs.Read(node, 0, len(plaintext)+10)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Errorf("read = %q (%v), want plaintext", got, err)
	}

	if err := env.fs.Open(node); err != nil {
		t.Fatal(err)
	}
	if n := len(env.srv.callsFor("dl")); n != 1 {
		t.Errorf("dl called %d times, want 1", n)
	}
}

func TestOpenRejectsTamperedCiphertext(t *testing.T) {
	env := newVFSEnv(t, "")
	ciphertext, metaHeader := e2eeFilePayload(t, []byte("victim bytes for the tamper case"))
	evil := append([]byte(nil), ciphertext...)
	evil[len(evil)/2] ^= 0x01
	env.srv.handle("dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-CLI-Metadata", metaHeader)
		w.Write(evil)
	})

	root := env.fs.Root
	root.Loaded = true
	node := NewFileNode("t.txt", "t.txt", int64(len(evil)), time.Now(), root)
	root.AddChild(node)
	id, _ := env.db.UpsertInode(nodeToInode(node, 0))
	node.ID = id
	env.fs.trackNode(node)

	err := env.fs.Open(node)
	if err == nil || !strings.Contains(err.Error(), "verify") {
		t.Fatalf("tampered ciphertext accepted: %v", err)
	}
	if node.Cached {
		t.Error("tampered content marked cached")
	}
	if node.OpenCount != 0 {
		t.Errorf("open count leaked on failure: %d", node.OpenCount)
	}
}

func TestOpenRefusesNonE2EEDownload(t *testing.T) {
	env := newVFSEnv(t, "")
	env.srv.handle("dl", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte("plain bytes, no metadata header"))
	})
	root := env.fs.Root
	root.Loaded = true
	node := NewFileNode("p.txt", "p.txt", 5, time.Now(), root)
	root.AddChild(node)

	if err := env.fs.Open(node); err == nil {
		t.Error("non-E2EE download accepted")
	}
}

func TestReadUncachedFails(t *testing.T) {
	env := newVFSEnv(t, "")
	node := NewFileNode("u.txt", "u.txt", 5, time.Now(), env.fs.Root)
	if _, err := env.fs.Read(node, 0, 5); err == nil {
		t.Error("read of uncached, non-dirty file succeeded")
	}
}
