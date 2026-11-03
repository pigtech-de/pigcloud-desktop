package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"pigcloud/internal/crypto"
	"pigcloud/internal/tree"
)

func testParentKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func testNodeID(t *testing.T) string {
	t.Helper()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(id)
}

func openSentRef(t *testing.T, opts map[string]string, nodeID string, parentKey []byte) []byte {
	t.Helper()
	sealed, ok := opts["e2ee_sealed_parent"]
	if !ok || sealed == "" {
		t.Fatalf("no e2ee_sealed_parent on the request")
	}
	blob, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatalf("e2ee_sealed_parent is not base64: %v", err)
	}
	idBytes, err := hex.DecodeString(nodeID)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := crypto.OpenParentRef(blob, idBytes, parentKey, nil)
	if err != nil {
		t.Fatalf("the sealed ref does not open under this node id and parent key: %v", err)
	}
	return parent
}

func TestToRootSendsTheRootFlagAndARootRefAndNamesNoParent(t *testing.T) {
	nodeID := testNodeID(t)
	parentKey := testParentKey(t)

	opts, err := restoreOptions(nodeID, restoreTarget{toRoot: true}, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if opts["to_root"] != "1" {
		t.Errorf("to_root = %q, want 1", opts["to_root"])
	}
	if _, named := opts["restore_parent_id"]; named {
		t.Error("to_root never travels with restore_parent_id")
	}
	if parent := openSentRef(t, opts, nodeID, parentKey); parent != nil {
		t.Errorf("sealed ref names parent %x, want root (nil)", parent)
	}
}

func TestResealedRootRefIsBoundToItsOwnNode(t *testing.T) {
	parentKey := testParentKey(t)
	mine := testNodeID(t)
	other := testNodeID(t)

	opts, err := restoreOptions(mine, restoreTarget{toRoot: true}, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := base64.StdEncoding.DecodeString(opts["e2ee_sealed_parent"])
	if err != nil {
		t.Fatal(err)
	}
	otherBytes, _ := hex.DecodeString(other)

	if _, err := crypto.OpenParentRef(blob, otherBytes, parentKey, nil); err == nil {
		t.Error("a ref sealed for one node opened under another's id")
	}
}

func TestAPlainRestoreNamesItsParentAndSealsTheRefToIt(t *testing.T) {
	nodeID := testNodeID(t)
	parentID := testNodeID(t)
	parentKey := testParentKey(t)

	opts, err := restoreOptions(nodeID, restoreTarget{parentID: parentID}, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := opts["to_root"]; ok {
		t.Error("a plain restore must not send to_root")
	}
	if opts["restore_parent_id"] != parentID {
		t.Errorf("restore_parent_id = %q, want %q", opts["restore_parent_id"], parentID)
	}
	if got := hex.EncodeToString(openSentRef(t, opts, nodeID, parentKey)); got != parentID {
		t.Errorf("the ref names %s, but the request names %s", got, parentID)
	}
}

func TestATopLevelRestoreNamesTheZeroIDWithARootRef(t *testing.T) {
	nodeID := testNodeID(t)
	parentKey := testParentKey(t)

	opts, err := restoreOptions(nodeID, restoreTarget{parentID: rootParentID}, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := opts["to_root"]; ok {
		t.Error("naming root by the zero id must not also send to_root")
	}
	if opts["restore_parent_id"] != rootParentID {
		t.Errorf("restore_parent_id = %q, want the zero id", opts["restore_parent_id"])
	}
	if parent := openSentRef(t, opts, nodeID, parentKey); parent != nil {
		t.Errorf("ref names %x, want the root sentinel", parent)
	}
}

func TestTheRestoreTargetIsTheParentTheTreeRecords(t *testing.T) {
	folder, inFolder, topLevel, lost := testNodeID(t), testNodeID(t), testNodeID(t), testNodeID(t)
	built := tree.New([]*tree.Node{
		{ID: folder, Name: "Docs", IsDir: true},
		{ID: inFolder, Name: "a.txt", ParentID: folder, Trashed: true},
		{ID: topLevel, Name: "b.txt", Trashed: true},
		{ID: lost, Name: "c.txt", ParentID: testNodeID(t), Trashed: true},
	})

	got, err := restoreTargetFor(built, inFolder)
	if err != nil || got.parentID != folder || got.toRoot {
		t.Errorf("trashed node in a folder: target %+v, %v; want parent %s", got, err, folder)
	}
	got, err = restoreTargetFor(built, topLevel)
	if err != nil || got.parentID != rootParentID || got.toRoot {
		t.Errorf("trashed top-level node: target %+v, %v; want the zero id", got, err)
	}
	if _, err := restoreTargetFor(built, lost); !errors.Is(err, errRestoreParentUnknown) {
		t.Errorf("an orphan's parent is unknown, got %v", err)
	}
	if _, err := restoreTargetFor(built, testNodeID(t)); err == nil {
		t.Error("a node the tree does not hold must refuse")
	}
}

func TestAPlainRestoreWithoutAParentIsRefused(t *testing.T) {
	if _, err := restoreOptions(testNodeID(t), restoreTarget{}, testParentKey(t)); err == nil {
		t.Error("a restore that names neither a folder nor the root must not be sent")
	}
}

func TestAnAccountWithoutKeysSendsTheLegacyRequest(t *testing.T) {
	opts, err := restoreOptions(testNodeID(t), restoreTarget{toRoot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts["to_root"] != "1" {
		t.Error("the opt-in must still ride for an account without keys")
	}
	if _, ok := opts["e2ee_sealed_parent"]; ok {
		t.Error("an account without keys has no parent key to seal with")
	}
}
