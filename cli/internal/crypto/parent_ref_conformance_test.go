package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type parentRefVectorFile struct {
	VectorKind      string          `json:"vector_kind"`
	SpecVersion     int             `json:"spec_version"`
	Description     string          `json:"description"`
	Generator       generatorMeta   `json:"generator"`
	Recipient       recipientKeys   `json:"recipient"`
	ParentKeyB64    string          `json:"parent_key_b64"`
	KeyContext      string          `json:"key_context"`
	OwnSealedLength int             `json:"own_sealed_length"`
	Cases           []parentRefCase `json:"cases"`
}

type parentRefCase struct {
	Label         string `json:"label"`
	ParentIDHex   string `json:"parent_id_hex"`
	NodeIDHex     string `json:"node_id_hex"`
	SealedBlobB64 string `json:"sealed_blob_b64"`
}

func TestConformance_ParentRefV1(t *testing.T) {
	path := vectorPath(t, "parent_ref_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateParentRefVector to create it", path, err)
	}
	var v parentRefVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "parent_ref" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if v.KeyContext != parentKeyContext {
		t.Fatalf("key context mismatch: fixture=%q impl=%q", v.KeyContext, parentKeyContext)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector has no cases")
	}

	priv := &PrivateKeySet{
		X25519: decode32(t, "x25519_sk", v.Recipient.X25519SkB64),
		Kyber:  decodeB64(t, "mlkem_seed", v.Recipient.MLKemSeedB64),
	}
	defer priv.Zero()

	parentKey, err := DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}
	if base64.StdEncoding.EncodeToString(parentKey) != v.ParentKeyB64 {
		t.Fatal("derived parent key diverges from the fixture")
	}

	for _, c := range v.Cases {
		sealed := decodeB64(t, c.Label+" sealed_blob", c.SealedBlobB64)
		nodeID, err := hex.DecodeString(c.NodeIDHex)
		if err != nil {
			t.Fatalf("%s: node id: %v", c.Label, err)
		}
		got, err := OpenParentRef(sealed, nodeID, parentKey, priv)
		if err != nil {
			t.Errorf("%s: OpenParentRef: %v", c.Label, err)
			continue
		}
		if hex.EncodeToString(got) != c.ParentIDHex {
			t.Errorf("%s: parent mismatch: got %q, want %q", c.Label, hex.EncodeToString(got), c.ParentIDHex)
		}
		wrongNode := append([]byte(nil), nodeID...)
		wrongNode[0] ^= 0xFF
		if _, err := OpenParentRef(sealed, wrongNode, parentKey, priv); err == nil {
			t.Errorf("%s: opened under a foreign node id", c.Label)
		}
	}

	parentID, _ := hex.DecodeString(v.Cases[0].ParentIDHex)
	nodeID, _ := hex.DecodeString(v.Cases[0].NodeIDHex)
	resealed, err := SealParentRef(parentID, nodeID, parentKey)
	if err != nil {
		t.Fatalf("SealParentRef: %v", err)
	}
	if len(resealed) != v.OwnSealedLength {
		t.Fatalf("own-write sealed length: got %d, want %d", len(resealed), v.OwnSealedLength)
	}
}
