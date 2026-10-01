package syncer

import (
	"context"
	"encoding/base64"
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

func TestChangedLocalBytesCannotAcceptAnEarlierAmbiguousUploadReplay(t *testing.T) {
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
	firstContext, cancelFirst := context.WithCancel(context.Background())
	defer cancelFirst()
	var mu sync.Mutex
	committed := make(map[string]string)
	var keys []string
	latest := ""
	loseFirstReply := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if request.URL.Query().Get("action") == "tee-attestation" {
			io.WriteString(w, `{"success":true,"enabled":false,"available":false}`)
			return
		}
		metadata, decodeErr := base64.StdEncoding.DecodeString(request.Header.Get(api.HeaderCliMetadata))
		var command api.CLIRequest
		if decodeErr != nil || json.Unmarshal(metadata, &command) != nil {
			t.Error("upload did not carry valid CLI metadata")
			http.Error(w, "bad metadata", 400)
			return
		}
		ciphertext, readErr := io.ReadAll(request.Body)
		sealed, sealedErr := base64.StdEncoding.DecodeString(command.Options["sealed_key"])
		dataKey, keyErr := crypto.UnsealDataKey(sealed, priv)
		metaRaw, metaErr := base64.StdEncoding.DecodeString(command.Options["encryption_meta"])
		var encMeta crypto.EncryptionMetadata
		if readErr != nil || sealedErr != nil || keyErr != nil || metaErr != nil || json.Unmarshal(metaRaw, &encMeta) != nil {
			t.Error("upload did not carry decryptable metadata")
			http.Error(w, "bad encryption", 400)
			return
		}
		plaintext, decryptErr := crypto.DecryptBytes(ciphertext, dataKey, &encMeta)
		if decryptErr != nil {
			t.Error(decryptErr)
			http.Error(w, "bad ciphertext", 400)
			return
		}
		key := command.Options["upload_idempotency_key"]
		mu.Lock()
		keys = append(keys, key)
		if _, replay := committed[key]; !replay {
			committed[key] = string(plaintext)
			latest = string(plaintext)
		}
		lose := loseFirstReply
		loseFirstReply = false
		mu.Unlock()
		if lose {
			cancelFirst()
			return
		}
		io.WriteString(w, `{"success":true,"node_id":"test-node"}`)
	}))
	t.Cleanup(server.Close)
	cfg := config.Get()
	oldEndpoint, oldKey := cfg.Endpoint, cfg.APIKey
	t.Cleanup(func() { cfg.Endpoint, cfg.APIKey = oldEndpoint, oldKey })
	cfg.Endpoint, cfg.APIKey = server.URL, "test"
	client := api.NewClient()
	local := t.TempDir()
	db, err := cache.Open(filepath.Join(local, ".pigcloud"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	tree := vfs.New("", db, nil, nil, client, pub, priv, nameKey, signPub, signPriv)
	writer := NewWritebackProcessor(tree, client, db, nil, local)
	file := filepath.Join(local, "notes.txt")
	writeFile(t, file, "AAA")
	id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 3, Dirty: true, SyncStatus: cache.StatusPending})
	if err != nil {
		t.Fatal(err)
	}
	db.EnqueueWriteback(id, "upload", "notes.txt", "")
	entries, err := db.DequeueWriteback(1, 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("queue: %+v %v", entries, err)
	}
	if _, err := writer.processUpload(firstContext, entries[0]); err == nil {
		t.Fatal("fixture did not lose the first commit response")
	}
	writeFile(t, file, "BBB")
	result, err := writer.processUpload(context.Background(), entries[0])
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	actual, distinct := latest, len(committed)
	firstKey, secondKey := keys[0], keys[len(keys)-1]
	mu.Unlock()
	if actual != "BBB" || distinct != 2 || firstKey == secondKey {
		t.Fatalf("changed plaintext reused old commit identity: remote=%q distinct=%d equalKeys=%v", actual, distinct, firstKey == secondKey)
	}
	if result.digest != digestOf("BBB") || result.etag != "" {
		t.Fatalf("legacy receipt claimed the wrong content proof: %+v", result)
	}
	if _, err := writer.processUpload(context.Background(), entries[0]); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	stable := keys[len(keys)-1] == secondKey && len(committed) == 2
	mu.Unlock()
	if !stable {
		t.Fatal("identical plaintext retry minted another commit identity")
	}
	writer.recordUploaded(entries[0], result.digest, result.etag)
	db.MarkSynced(id, result.etag)
	writeFile(t, file, "CCC")
	db.SetRemoteVersion(id, "new-remote-version")
	db.InvalidateCache(id)
	NewReconciler(local, "", db, time.Minute).Reconcile(context.Background())
	inode, err := db.GetInode(id)
	if err != nil || !inode.Dirty || inode.SyncStatus != cache.StatusConflict {
		t.Fatalf("a later local edit lost its conflict under an unknown receipt version: %+v %v", inode, err)
	}
}

func TestUnknownUploadVersionDownloadsTransformedContentOnlyOverAnUnchangedLocalBaseline(t *testing.T) {
	for _, changed := range []bool{false, true} {
		d, db, local := newDownloader(t, "")
		file := filepath.Join(local, "notes.txt")
		writeFile(t, file, "submitted")
		id, err := db.UpsertInode(&cache.Inode{RemotePath: "notes.txt", DisplayName: "notes.txt", Size: 9, Dirty: true, SyncStatus: cache.StatusPending})
		if err != nil {
			t.Fatal(err)
		}
		writer := NewWritebackProcessor(d.vfs, nil, db, nil, local)
		writer.recordUploaded(&cache.WritebackEntry{InodeID: id, RemotePath: "notes.txt"}, digestOf("submitted"), "")
		db.MarkSynced(id, "")
		if changed {
			writeFile(t, file, "edited later")
		}
		db.SetRemoteVersion(id, "transformed-version")
		db.InvalidateCache(id)
		node := vfs.NewFileNode("notes.txt", "notes.txt", 9, time.Now(), nil)
		node.ID, node.Etag = id, "transformed-version"
		fetched := 0
		d.fetchFile = func(context.Context, string) ([]byte, *api.DownloadResult, error) {
			fetched++
			return []byte("sanitized"), &api.DownloadResult{}, nil
		}
		var downloaded, skipped int64
		var tasks sync.WaitGroup
		if err := d.walkAndSync(context.Background(), node, &downloaded, &skipped, &tasks); err != nil {
			t.Fatal(err)
		}
		tasks.Wait()
		actual, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		inode, err := db.GetInode(id)
		if err != nil {
			t.Fatal(err)
		}
		if changed {
			if string(actual) != "edited later" || fetched != 0 || inode.SyncStatus != cache.StatusConflict {
				t.Fatalf("unknown upload version overwrote a later local edit: %q fetched=%d status=%s", actual, fetched, inode.SyncStatus)
			}
		} else if string(actual) != "sanitized" || fetched != 1 || inode.Dirty {
			t.Fatalf("unchanged submitted bytes did not converge to transformed content: %q fetched=%d dirty=%v", actual, fetched, inode.Dirty)
		}
	}
}
