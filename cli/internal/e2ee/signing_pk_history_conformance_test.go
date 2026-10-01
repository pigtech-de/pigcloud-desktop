package e2ee

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func loadSigningPkHistoryVector(t *testing.T) (blobJSON, edPub, mldsaPub []byte) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", "signing_pk_history_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v struct {
		VectorKind string `json:"vector_kind"`
		Domain     string `json:"domain"`
		SigningPub struct {
			Ed25519B64 string `json:"ed25519_b64"`
			Mldsa44B64 string `json:"mldsa44_b64"`
		} `json:"signing_pub"`
		Blob json.RawMessage `json:"blob"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.VectorKind != "signing_pk_history_v1" {
		t.Fatalf("unexpected vector kind %q", v.VectorKind)
	}
	if v.Domain != signingPkHistoryDomain {
		t.Fatalf("domain drift: vector %q != production %q", v.Domain, signingPkHistoryDomain)
	}
	edPub = decodeVecB64(t, v.SigningPub.Ed25519B64)
	mldsaPub = decodeVecB64(t, v.SigningPub.Mldsa44B64)
	return []byte(v.Blob), edPub, mldsaPub
}

func decodeVecB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	return b
}

func flipBlobSig(t *testing.T, blobJSON []byte, field string) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(blobJSON, &m); err != nil {
		t.Fatalf("unmarshal blob: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(m[field].(string))
	if err != nil {
		t.Fatalf("decode %s: %v", field, err)
	}
	raw[0] ^= 0x01
	m[field] = base64.StdEncoding.EncodeToString(raw)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal blob: %v", err)
	}
	return out
}

func TestConformance_SigningPkHistoryV1(t *testing.T) {
	blobJSON, edPub, mldsaPub := loadSigningPkHistoryVector(t)

	if got := verifySigningPkHistory(blobJSON, edPub, mldsaPub); len(got) != 2 {
		t.Fatalf("valid blob: expected 2 eds, got %d", len(got))
	}

	if verifySigningPkHistory(flipBlobSig(t, blobJSON, "sig_ml"), edPub, mldsaPub) != nil {
		t.Error("tampered ML-DSA signature accepted (PQ downgrade)")
	}
	if verifySigningPkHistory(flipBlobSig(t, blobJSON, "sig_ed"), edPub, mldsaPub) != nil {
		t.Error("tampered Ed25519 signature accepted")
	}
	if verifySigningPkHistory(blobJSON, edPub, nil) != nil {
		t.Error("missing ML-DSA anchor accepted (strict-AND needs both pubs)")
	}
	wrongMl := append([]byte(nil), mldsaPub...)
	wrongMl[0] ^= 0x01
	if verifySigningPkHistory(blobJSON, edPub, wrongMl) != nil {
		t.Error("wrong ML-DSA anchor accepted")
	}
	if verifySigningPkHistory(blobJSON, randKey(t, ed25519.PublicKeySize), mldsaPub) != nil {
		t.Error("wrong Ed25519 anchor accepted")
	}
}
