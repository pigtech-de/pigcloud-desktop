package crypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type keyBundleVectorFile struct {
	VectorKind string `json:"vector_kind"`
	Domain     string `json:"domain"`
	Bundle     struct {
		X25519B64  string `json:"x25519_b64"`
		KyberB64   string `json:"kyber_b64"`
		Ed25519B64 string `json:"ed25519_b64"`
		Mldsa44B64 string `json:"mldsa44_b64"`
	} `json:"bundle"`
	Blob struct {
		V     int    `json:"v"`
		SigEd string `json:"sig_ed"`
		SigMl string `json:"sig_ml"`
	} `json:"blob"`
}

func loadKeyBundleVector(t *testing.T) keyBundleVectorFile {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", "key_bundle_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key_bundle_v1.json: %v", err)
	}
	var v keyBundleVectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse key_bundle_v1.json: %v", err)
	}
	if v.VectorKind != "key_bundle_v1" {
		t.Fatalf("vector_kind = %q, want key_bundle_v1", v.VectorKind)
	}
	if v.Domain != KeyBundleDomain {
		t.Fatalf("vector domain %q does not match the shipped KeyBundleDomain %q", v.Domain, KeyBundleDomain)
	}
	return v
}

func vectorBundleAndSigs(t *testing.T, v keyBundleVectorFile) (*KeyBundle, []byte, []byte) {
	t.Helper()
	return &KeyBundle{
		X25519:  decodeB64(t, "bundle x25519", v.Bundle.X25519B64),
		Kyber:   decodeB64(t, "bundle mlkem", v.Bundle.KyberB64),
		Ed25519: decodeB64(t, "bundle ed25519", v.Bundle.Ed25519B64),
		Mldsa:   decodeB64(t, "bundle mldsa44", v.Bundle.Mldsa44B64),
	}, decodeB64(t, "sig_ed", v.Blob.SigEd), decodeB64(t, "sig_ml", v.Blob.SigMl)
}

func TestKeyBundleVectorVerifies(t *testing.T) {
	v := loadKeyBundleVector(t)
	bundle, sigEd, sigMl := vectorBundleAndSigs(t, v)
	if !VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("committed key_bundle_v1 vector must verify against the shipped VerifyKeyBundle")
	}
}

func TestKeyBundleRejectsTamperedSignatures(t *testing.T) {
	v := loadKeyBundleVector(t)

	bundle, sigEd, sigMl := vectorBundleAndSigs(t, v)
	sigMl[0] ^= 0x01
	if VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("a tampered ML-DSA signature must reject; accepting it is the PQ downgrade of SEC-E2EE-23")
	}

	bundle, sigEd, sigMl = vectorBundleAndSigs(t, v)
	sigEd[0] ^= 0x01
	if VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("a tampered Ed25519 signature must reject")
	}
}

func TestKeyBundleRejectsSubstitutedKemHalves(t *testing.T) {
	v := loadKeyBundleVector(t)

	bundle, sigEd, sigMl := vectorBundleAndSigs(t, v)
	bundle.X25519[0] ^= 0x01
	if VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("a substituted X25519 half must reject; this binding is what stops a server swapping a pinned peer's seal key")
	}

	bundle, sigEd, sigMl = vectorBundleAndSigs(t, v)
	bundle.Kyber[0] ^= 0x01
	if VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("a substituted ML-KEM half must reject")
	}
}

func TestKeyBundleRejectsWrongLengthField(t *testing.T) {
	v := loadKeyBundleVector(t)
	bundle, sigEd, sigMl := vectorBundleAndSigs(t, v)
	bundle.Kyber = bundle.Kyber[:len(bundle.Kyber)-1]
	if VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("a short field must reject; unprefixed concatenation makes two bundles share one signed input")
	}
}

func TestKeyBundleRoundTripsThroughSignKeyBundle(t *testing.T) {
	kemPub, kemPriv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer kemPriv.Zero()
	signPub, signPriv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}
	defer signPriv.Zero()

	bundle := &KeyBundle{X25519: kemPub.X25519[:], Kyber: kemPub.Kyber, Ed25519: signPub.Ed25519[:], Mldsa: signPub.Mldsa}
	sigEd, sigMl, err := SignKeyBundle(bundle, signPriv)
	if err != nil {
		t.Fatalf("SignKeyBundle: %v", err)
	}
	if !VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("SignKeyBundle output must verify under VerifyKeyBundle")
	}
}
