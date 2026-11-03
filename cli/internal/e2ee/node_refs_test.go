package e2ee

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/crypto"
)

type folderServer struct {
	existing     map[string]string
	mkCalls      []map[string]string
	refuseFirst  string
	echo         bool
	createdLater map[string]string
}

func (f *folderServer) Execute(_ context.Context, command string, options map[string]string) (*api.Response, error) {
	switch command {
	case "in":
		id, ok := f.existing[strings.TrimPrefix(options["source"], "/")]
		if !ok {
			return &api.Response{StatusCode: http.StatusNotFound}, nil
		}
		raw := fmt.Sprintf(`{"success":true,"details":{"nodeId":%q,"type":"directory"}}`, id)
		return &api.Response{Success: true, StatusCode: 200, Raw: json.RawMessage(raw)}, nil
	case "mk":
		f.mkCalls = append(f.mkCalls, options)
		if f.refuseFirst != "" {
			code := f.refuseFirst
			f.refuseFirst = ""
			for p, id := range f.createdLater {
				f.existing[p] = id
			}
			return &api.Response{StatusCode: http.StatusConflict, ErrorCode: code, Message: code}, nil
		}
		var segments []map[string]string
		_ = json.Unmarshal([]byte(options["e2ee_path_segments"]), &segments)
		parts := strings.Split(strings.Trim(options["source"], "/"), "/")
		var echo []SegmentID
		for i, seg := range segments {
			p := strings.Join(parts[:i+1], "/")
			if id, ok := f.existing[p]; ok {
				echo = append(echo, SegmentID{NodeID: id, Existed: true})
				continue
			}
			f.existing[p] = seg["node_id"]
			echo = append(echo, SegmentID{NodeID: seg["node_id"]})
		}
		body := map[string]any{"success": true}
		if f.echo {
			body["segment_ids"] = echo
		}
		raw, _ := json.Marshal(body)
		return &api.Response{Success: true, StatusCode: 200, Raw: raw}, nil
	}
	return &api.Response{StatusCode: http.StatusBadRequest}, nil
}

func sentSegments(t *testing.T, options map[string]string) []map[string]string {
	t.Helper()
	var segments []map[string]string
	if err := json.Unmarshal([]byte(options["e2ee_path_segments"]), &segments); err != nil {
		t.Fatalf("e2ee_path_segments: %v", err)
	}
	return segments
}

func openSegmentRef(t *testing.T, seg map[string]string, parentKey []byte) string {
	t.Helper()
	blob, err := base64.StdEncoding.DecodeString(seg["sealed_parent"])
	if err != nil {
		t.Fatalf("sealed_parent: %v", err)
	}
	id, err := hex.DecodeString(seg["node_id"])
	if err != nil || len(id) != 16 {
		t.Fatalf("node_id %q", seg["node_id"])
	}
	parent, err := crypto.OpenParentRef(blob, id, parentKey, nil)
	if err != nil {
		t.Fatalf("segment ref does not open under its own id: %v", err)
	}
	return hex.EncodeToString(parent)
}

func TestEnsureFolderChainSendsEachRefWithItsOwnSegment(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)
	parentKey, err := crypto.DeriveParentKey(f.priv)
	if err != nil {
		t.Fatal(err)
	}
	const aID, bID, cID = "a0000000000000000000000000000000", "b0000000000000000000000000000000", "c0000000000000000000000000000000"
	cases := []struct {
		name     string
		existing map[string]string
		newFrom  int
		ancestor string
	}{
		{"no segment exists", map[string]string{}, 0, ""},
		{"one segment exists", map[string]string{"A": aID}, 1, aID},
		{"every segment exists", map[string]string{"A": aID, "A/B": bID, "A/B/C": cID}, 3, cID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &folderServer{existing: tc.existing, echo: true}
			chain, err := EnsureFolderChain(context.Background(), server, "/A/B/C", parentKey)
			if err != nil || chain.Resp == nil || !chain.Resp.Success {
				t.Fatalf("chain: %+v %v", chain, err)
			}
			if len(server.mkCalls) != 1 {
				t.Fatalf("mk calls = %d", len(server.mkCalls))
			}
			segments := sentSegments(t, server.mkCalls[0])
			if len(segments) != 3 {
				t.Fatalf("segments = %d", len(segments))
			}
			want := tc.ancestor
			for i, seg := range segments {
				if i < tc.newFrom {
					if seg["node_id"] != "" || seg["sealed_parent"] != "" {
						t.Errorf("existing segment %d carries %v", i, seg)
					}
					continue
				}
				if got := openSegmentRef(t, seg, parentKey); got != want {
					t.Errorf("segment %d ref names %q, want %q", i, got, want)
				}
				want = seg["node_id"]
			}
			if chain.LeafID != want || chain.Created != (tc.newFrom < 3) {
				t.Errorf("leaf %q created=%v, want %q created=%v", chain.LeafID, chain.Created, want, tc.newFrom < 3)
			}
		})
	}
}

func TestEnsureFolderChainReprobesOnceAfterPathChanged(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)
	parentKey, _ := crypto.DeriveParentKey(f.priv)
	const aID = "a1000000000000000000000000000000"
	server := &folderServer{existing: map[string]string{}, echo: true, refuseFirst: CodePathChanged, createdLater: map[string]string{"A": aID}}

	chain, err := EnsureFolderChain(context.Background(), server, "/A/B", parentKey)
	if err != nil || !chain.Resp.Success {
		t.Fatalf("chain: %+v %v", chain, err)
	}
	if len(server.mkCalls) != 2 {
		t.Fatalf("mk calls = %d, want the refused one and one retry", len(server.mkCalls))
	}
	retry := sentSegments(t, server.mkCalls[1])
	if retry[0]["node_id"] != "" {
		t.Errorf("the retry still claims an id for the segment that now exists: %v", retry[0])
	}
	if got := openSegmentRef(t, retry[1], parentKey); got != aID {
		t.Errorf("retry seals B to %q, want the real A %q", got, aID)
	}
}

func TestEnsureFolderChainAsksForTheLeafWhenAnOlderServerEchoesNothing(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)
	parentKey, _ := crypto.DeriveParentKey(f.priv)
	server := &folderServer{existing: map[string]string{}}

	chain, err := EnsureFolderChain(context.Background(), server, "/A", parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if chain.LeafID != server.existing["A"] || chain.LeafID == "" {
		t.Errorf("leaf %q, server stored %q", chain.LeafID, server.existing["A"])
	}
}

func TestChainSegmentRefsWithoutAParentKeyRefuses(t *testing.T) {
	if _, err := ChainSegmentRefs(2, 0, "", nil); err == nil {
		t.Error("a locked session minted refs it could not seal")
	}
}
