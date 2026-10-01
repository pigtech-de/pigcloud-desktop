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

type recordedCall struct {
	Command string            `json:"command"`
	Options map[string]string `json:"options"`
}

func scopeServer(t *testing.T, pub *crypto.PublicKeySet, treeWorks bool, nodeID, name string) (*httptest.Server, *[]recordedCall) {
	t.Helper()
	calls := &[]recordedCall{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var call recordedCall
		_ = json.Unmarshal(body, &call)
		*calls = append(*calls, call)

		w.Header().Set("Content-Type", "application/json")
		switch call.Command {
		case "e2ee_shell_digest":
			io.WriteString(w, `{"success":true,"digest":"d1","count":1}`)
		case "e2ee_list_shells":
			if !treeWorks {
				io.WriteString(w, `{"success":false,"message":"nope"}`)
				return
			}
			sealedName, err := crypto.SealDisplayName(name, pub)
			if err != nil {
				t.Errorf("SealDisplayName: %v", err)
			}
			shell := map[string]any{
				"node_id": nodeID, "item_type": "file", "file_size": 10,
				"created_at": 1, "modified_at": 1,
				"e2ee_display_name": base64.StdEncoding.EncodeToString(sealedName),
			}
			out, _ := json.Marshal(map[string]any{
				"success": true, "shells": []any{shell}, "done": true, "next_cursor": nil,
			})
			w.Write(out)
		default:
			io.WriteString(w, `{"success":true,"entries":[]}`)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, calls
}

func scopeFixture(t *testing.T, treeWorks bool, nodeID, name string) (*Poller, *[]recordedCall) {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

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

	srv, calls := scopeServer(t, pub, treeWorks, nodeID, name)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "test"
	client := api.NewClient()

	v := vfs.New("", db, nil, nil, client, pub, priv, nameKey, nil, nil)
	v.Root.Loaded = true

	return NewPoller(v, client, db, time.Minute), calls
}

func lsCallFrom(calls []recordedCall) (recordedCall, bool) {
	for _, call := range calls {
		if call.Command == "ls" {
			return call, true
		}
	}
	return recordedCall{}, false
}

func TestPollNamesChildrenFromItsOwnTree(t *testing.T) {
	nodeID := "0123456789abcdef0123456789abcdef"
	p, calls := scopeFixture(t, true, nodeID, "report.txt")

	p.poll(context.Background())

	ls, ok := lsCallFrom(*calls)
	if !ok {
		t.Fatal("the poll never issued an ls")
	}
	raw, ok := ls.Options["scope_node_ids"]
	if !ok {
		t.Fatal("poll did not name the directory's children, so the server still has to walk parent_id")
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		t.Fatalf("scope is not a json id list: %v", err)
	}
	if len(ids) != 1 || ids[0] != nodeID {
		t.Fatalf("scope = %v, want the one root child %s", ids, nodeID)
	}
}

func TestPollFallsBackToTheServerWalkWhenNoTreeBuilds(t *testing.T) {
	p, calls := scopeFixture(t, false, "0123456789abcdef0123456789abcdef", "report.txt")

	p.poll(context.Background())

	ls, ok := lsCallFrom(*calls)
	if !ok {
		t.Fatal("the poll never issued an ls")
	}
	if _, present := ls.Options["scope_node_ids"]; present {
		t.Fatal("an unbuildable tree must leave the server walking, never send an empty scope")
	}
}
