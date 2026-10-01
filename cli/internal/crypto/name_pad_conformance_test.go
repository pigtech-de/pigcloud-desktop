package crypto

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
)

type displayNamePadVectorFile struct {
	VectorKind        string               `json:"vector_kind"`
	SpecVersion       int                  `json:"spec_version"`
	Description       string               `json:"description"`
	Generator         generatorMeta        `json:"generator"`
	Recipient         recipientKeys        `json:"recipient"`
	SealOverheadBytes int                  `json:"seal_overhead_bytes"`
	HeaderBytes       int                  `json:"header_bytes"`
	Buckets           []int                `json:"buckets"`
	Cases             []displayNamePadCase `json:"cases"`
}

type displayNamePadCase struct {
	Label              string `json:"label"`
	Note               string `json:"note"`
	NameB64            string `json:"name_b64"`
	SealedBlobB64      string `json:"sealed_blob_b64"`
	PaddedPlaintextLen int    `json:"padded_plaintext_len"`
	Legacy             bool   `json:"legacy"`
}

func TestConformance_DisplayNamePadV1(t *testing.T) {
	path := vectorPath(t, "display_name_pad_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateDisplayNamePadVector to create it", path, err)
	}
	var v displayNamePadVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "display_name_pad" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if len(v.Cases) == 0 {
		t.Fatal("vector has no cases")
	}

	priv := &PrivateKeySet{
		X25519: decode32(t, "x25519_sk", v.Recipient.X25519SkB64),
		Kyber:  decodeB64(t, "mlkem_seed", v.Recipient.MLKemSeedB64),
	}
	defer priv.Zero()
	pub := &PublicKeySet{
		X25519: decode32(t, "x25519_pk", v.Recipient.X25519PkB64),
		Kyber:  decodeB64(t, "mlkem_pk", v.Recipient.MLKemPkB64),
	}

	for _, c := range v.Cases {
		sealed := decodeB64(t, c.Label+" sealed_blob", c.SealedBlobB64)
		wantName := string(decodeB64(t, c.Label+" name", c.NameB64))

		got, err := UnsealDisplayName(sealed, priv)
		if err != nil {
			t.Errorf("%s: UnsealDisplayName: %v", c.Label, err)
			continue
		}
		if got != wantName {
			t.Errorf("%s: name mismatch: got %q, want %q", c.Label, got, wantName)
		}

		plain, err := HybridUnseal(sealed, priv)
		if err != nil {
			t.Errorf("%s: HybridUnseal: %v", c.Label, err)
			continue
		}
		if len(plain) != c.PaddedPlaintextLen {
			t.Errorf("%s: padded plaintext length: got %d, want %d", c.Label, len(plain), c.PaddedPlaintextLen)
		}

		if !c.Legacy {
			resealed, err := SealDisplayName(wantName, pub)
			if err != nil {
				t.Errorf("%s: SealDisplayName: %v", c.Label, err)
				continue
			}
			if len(resealed) != v.SealOverheadBytes+c.PaddedPlaintextLen {
				t.Errorf("%s: sealed length: got %d, want %d", c.Label, len(resealed), v.SealOverheadBytes+c.PaddedPlaintextLen)
			}
			resealed2, err := SealDisplayName(wantName, pub)
			if err == nil && base64.StdEncoding.EncodeToString(resealed) == base64.StdEncoding.EncodeToString(resealed2) {
				t.Errorf("%s: two seals of the same name must differ (randomized seal)", c.Label)
			}
		}
	}
}
