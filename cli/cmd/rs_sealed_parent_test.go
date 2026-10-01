package cmd

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"pigcloud/internal/crypto"
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

func TestRootRestoreCarriesAResealedRootParentRef(t *testing.T) {
	nodeID := testNodeID(t)
	parentKey := testParentKey(t)

	opts := restoreOptions(nodeID, true, parentKey)

	if opts["to_root"] != "1" {
		t.Errorf("to_root = %q, want 1", opts["to_root"])
	}
	sealed, ok := opts["e2ee_sealed_parent"]
	if !ok || sealed == "" {
		t.Fatalf("no e2ee_sealed_parent on the request: the restored node keeps a ref to the folder that no longer exists")
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
	if parent != nil {
		t.Errorf("sealed ref names parent %x, want root (nil)", parent)
	}
}

func TestResealedRootRefIsBoundToItsOwnNode(t *testing.T) {
	parentKey := testParentKey(t)
	mine := testNodeID(t)
	other := testNodeID(t)

	sealed := restoreOptions(mine, true, parentKey)["e2ee_sealed_parent"]
	blob, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil {
		t.Fatal(err)
	}
	otherBytes, _ := hex.DecodeString(other)

	if _, err := crypto.OpenParentRef(blob, otherBytes, parentKey, nil); err == nil {
		t.Error("a ref sealed for one node opened under another's id: the AAD binding is gone")
	}
}

func TestAPlainRestoreSendsNoRootOptions(t *testing.T) {
	opts := restoreOptions(testNodeID(t), false, testParentKey(t))

	if _, ok := opts["to_root"]; ok {
		t.Error("a plain restore must not opt into the root landing")
	}
	if _, ok := opts["e2ee_sealed_parent"]; ok {
		t.Error("a plain restore keeps its parent, so re-sealing the ref to root would corrupt it")
	}
}

func TestRootRestoreOmitsTheRefWhenTheParentKeyIsUnavailable(t *testing.T) {
	opts := restoreOptions(testNodeID(t), true, nil)

	if opts["to_root"] != "1" {
		t.Error("the opt-in must still ride, or a locked client cannot restore at all")
	}
	if _, ok := opts["e2ee_sealed_parent"]; ok {
		t.Error("no parent key means no ref; sending an empty one would blank a good ref server-side")
	}
}
