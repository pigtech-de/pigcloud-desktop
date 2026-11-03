package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type publicLinkAccessVector struct {
	VectorKind string `json:"vector_kind"`
	AccessInfo string `json:"access_info"`
	Cases      []struct {
		LinkKeyHex    string `json:"link_key_hex"`
		ProofB64URL   string `json:"proof_b64url"`
		AccessHashB64 string `json:"access_hash_b64"`
	} `json:"cases"`
}

func TestConformance_PublicLinkAccessV1(t *testing.T) {
	raw, err := os.ReadFile(vectorPath(t, "public_link_access_v1.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var v publicLinkAccessVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "public_link_access_v1" || v.AccessInfo != publicLinkAccessInfo {
		t.Fatalf("fixture kind=%q info=%q, this impl info=%q", v.VectorKind, v.AccessInfo, publicLinkAccessInfo)
	}
	if len(v.Cases) == 0 {
		t.Fatalf("fixture has no cases")
	}
	for _, c := range v.Cases {
		key, err := hex.DecodeString(c.LinkKeyHex)
		if err != nil {
			t.Fatalf("link_key_hex: %v", err)
		}
		proof, err := DerivePublicLinkAccessProof(key)
		if err != nil {
			t.Fatalf("DerivePublicLinkAccessProof: %v", err)
		}
		if got := base64.RawURLEncoding.EncodeToString(proof); got != c.ProofB64URL {
			t.Errorf("proof mismatch for %s\n  got:  %s\n  want: %s", c.LinkKeyHex, got, c.ProofB64URL)
		}
		hash, err := PublicLinkAccessHash(key)
		if err != nil {
			t.Fatalf("PublicLinkAccessHash: %v", err)
		}
		if got := base64.StdEncoding.EncodeToString(hash); got != c.AccessHashB64 {
			t.Errorf("access hash mismatch for %s\n  got:  %s\n  want: %s", c.LinkKeyHex, got, c.AccessHashB64)
		}
	}
}
