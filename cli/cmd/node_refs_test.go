package cmd

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
	"pigcloud/internal/e2ee"
	"pigcloud/internal/tree"
)

func derivedParentKey(t *testing.T) []byte {
	t.Helper()
	_, priv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.DeriveParentKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func openRef(t *testing.T, nodeID, sealed string, parentKey []byte) string {
	t.Helper()
	blob, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("ref for %s is not base64: %v", nodeID, err)
	}
	id, err := hex.DecodeString(nodeID)
	if err != nil || len(id) != 16 {
		t.Fatalf("id %q is not 16 bytes of hex", nodeID)
	}
	parent, err := crypto.OpenParentRef(blob, id, parentKey, nil)
	if err != nil {
		t.Fatalf("ref for %s does not open under its own id: %v", nodeID, err)
	}
	return hex.EncodeToString(parent)
}

func TestTheCopyMapSealsEveryCopyToItsCopiedParent(t *testing.T) {
	key := derivedParentKey(t)
	src, sub, file, hidden, under := testNodeID(t), testNodeID(t), testNodeID(t), testNodeID(t), testNodeID(t)
	built := tree.New([]*tree.Node{
		{ID: src, Name: "Photos", IsDir: true},
		{ID: sub, Name: "2026", ParentID: src, IsDir: true},
		{ID: file, Name: "a.jpg", ParentID: sub},
		{ID: hidden, Name: e2ee.NameUnavailable, ParentID: src, IsDir: true},
		{ID: under, Name: "b.jpg", ParentID: hidden},
	})
	dest := testNodeID(t)
	var sealedPaths []string
	seal := func(name, fullPath string) (subtreeNameEntry, error) {
		sealedPaths = append(sealedPaths, fullPath)
		return subtreeNameEntry{DisplayName: name, PathToken: fullPath}, nil
	}

	copyMap, names, err := buildCopyMap(built, src, dest, "/Backup/Photos", key, seal)
	if err != nil {
		t.Fatal(err)
	}
	parentOf := map[string]string{src: dest, sub: copyMap[src].NodeID, file: copyMap[sub].NodeID, hidden: copyMap[src].NodeID, under: copyMap[hidden].NodeID}
	seen := map[string]bool{}
	for source, want := range parentOf {
		entry, ok := copyMap[source]
		if !ok {
			t.Fatalf("no copy entry for %s", source)
		}
		if seen[entry.NodeID] {
			t.Fatalf("copy id %s minted twice", entry.NodeID)
		}
		seen[entry.NodeID] = true
		if got := openRef(t, entry.NodeID, entry.SealedParent, key); got != want {
			t.Errorf("copy of %s sealed to %s, want %s", source, got, want)
		}
	}
	if len(copyMap) != len(parentOf) {
		t.Errorf("copy map holds %d entries, want %d", len(copyMap), len(parentOf))
	}
	if len(names) != 2 || names[sub].PathToken != "Backup/Photos/2026" || names[file].PathToken != "Backup/Photos/2026/a.jpg" {
		t.Errorf("names %v sealed %v", names, sealedPaths)
	}
}

func TestAFileCopyMapHoldsOnlyTheRootSealedToTheDestination(t *testing.T) {
	key := derivedParentKey(t)
	src, dest := testNodeID(t), testNodeID(t)
	copyMap, names, err := buildCopyMap(nil, src, dest, "/x.txt", key, nil)
	if err != nil || len(copyMap) != 1 || names != nil {
		t.Fatalf("map %v names %v err %v", copyMap, names, err)
	}
	if got := openRef(t, copyMap[src].NodeID, copyMap[src].SealedParent, key); got != dest {
		t.Errorf("file copy sealed to %s, want %s", got, dest)
	}
}

type pathServer struct {
	mu      sync.Mutex
	dirs    map[string]string
	files   map[string]string
	inCalls map[string]int
	mk      func(w http.ResponseWriter)
	after   map[string]string
}

func (s *pathServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req api.CLIRequest
	_ = json.Unmarshal(body, &req)
	w.Header().Set("Content-Type", "application/json")
	s.mu.Lock()
	defer s.mu.Unlock()
	switch req.Command {
	case "in":
		source := req.Options["source"]
		if s.inCalls == nil {
			s.inCalls = map[string]int{}
		}
		s.inCalls[source]++
		if id, ok := s.dirs[source]; ok {
			fmt.Fprintf(w, `{"success":true,"details":{"nodeId":%q,"type":"directory"}}`, id)
			return
		}
		if id, ok := s.files[source]; ok {
			fmt.Fprintf(w, `{"success":true,"details":{"nodeId":%q,"type":"file"}}`, id)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"success":false,"message":"not found"}`)
	case "mk":
		for p, id := range s.after {
			s.dirs[p] = id
		}
		s.mk(w)
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"success":false}`)
	}
}

func TestAMoveSealsTheMovedNodeToItsDestinationFolder(t *testing.T) {
	key := derivedParentKey(t)
	moved, archive := testNodeID(t), testNodeID(t)
	ts := httptest.NewServer(&pathServer{dirs: map[string]string{"/Archive": archive}, files: map[string]string{"/Docs/a.txt": moved}})
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	options := map[string]string{}
	if remint := addMoveRef(context.Background(), options, "/Docs/a.txt", "/Archive", "/Archive/a.txt", key); remint != nil {
		t.Error("a move mints no id, so it has nothing to re-mint")
	}
	if got := openRef(t, moved, options["e2ee_sealed_parent"], key); got != archive {
		t.Errorf("moved node sealed to %s, want %s", got, archive)
	}
	if _, ok := options["e2ee_node_id"]; ok {
		t.Error("a move must not send a new node id")
	}
}

func TestAChildFolderCreatedConcurrentlyTakesTheServersID(t *testing.T) {
	key := derivedParentKey(t)
	parent, theirs := testNodeID(t), testNodeID(t)
	srv := &pathServer{
		dirs:  map[string]string{},
		after: map[string]string{"/Docs/Sub": theirs},
		mk: func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusConflict)
			fmt.Fprint(w, `{"success":false,"errorCode":"path_exists","message":"exists"}`)
		},
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	withTestEndpoint(t, ts.URL)

	dirs := &remoteDirSet{ids: map[string]string{"/Docs": parent}, fresh: map[string]bool{}, parentKey: key}
	if err := dirs.ensureChild(context.Background(), api.NewClient(), "/Docs/Sub"); err != nil {
		t.Fatal(err)
	}
	if dirs.ids["/Docs/Sub"] != theirs {
		t.Errorf("recorded %q, want the server's %q", dirs.ids["/Docs/Sub"], theirs)
	}
	if dirs.fresh["/Docs/Sub"] {
		t.Error("a folder someone else created is not fresh: its children may exist")
	}
}
