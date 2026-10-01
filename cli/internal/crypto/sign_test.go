package crypto

import (
	"bytes"
	"testing"
)

func TestGenerateSigningKeyPair(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}
	if pub.Ed25519 == [Ed25519PKSize]byte{} {
		t.Error("ed25519 public key is all zeros")
	}
	if len(pub.Mldsa) != Mldsa44PKSize {
		t.Errorf("mldsa pk length = %d, want %d", len(pub.Mldsa), Mldsa44PKSize)
	}
	if len(priv.Ed25519) != Ed25519SKSize {
		t.Errorf("ed25519 sk length = %d, want %d", len(priv.Ed25519), Ed25519SKSize)
	}
	if len(priv.Mldsa) != Mldsa44SKSize {
		t.Errorf("mldsa sk length = %d, want %d", len(priv.Mldsa), Mldsa44SKSize)
	}

	pub2, _, _ := GenerateSigningKeyPair()
	if pub.Ed25519 == pub2.Ed25519 {
		t.Error("two keypairs have identical ed25519 public keys")
	}
	if bytes.Equal(pub.Mldsa, pub2.Mldsa) {
		t.Error("two keypairs have identical mldsa public keys")
	}
}

func TestSignFileBytesRoundTrip(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}

	ciphertext := bytes.Repeat([]byte{0xAB, 0xCD, 0xEF}, 5000)

	sigEd, sigMl, err := SignFileBytes(bytes.NewReader(ciphertext), priv)
	if err != nil {
		t.Fatalf("SignFileBytes: %v", err)
	}
	if len(sigEd) != Ed25519SigSize {
		t.Errorf("ed25519 sig length = %d, want %d", len(sigEd), Ed25519SigSize)
	}
	if len(sigMl) != Mldsa44SigSize {
		t.Errorf("mldsa sig length = %d, want %d", len(sigMl), Mldsa44SigSize)
	}

	if err := VerifyFileSignatures(bytes.NewReader(ciphertext), sigEd, sigMl, pub); err != nil {
		t.Errorf("VerifyFileSignatures roundtrip: %v", err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[100] ^= 0xFF
	if err := VerifyFileSignatures(bytes.NewReader(tampered), sigEd, sigMl, pub); err == nil {
		t.Error("tampered ciphertext verified — expected failure")
	}

	otherPub, _, _ := GenerateSigningKeyPair()
	if err := VerifyFileSignatures(bytes.NewReader(ciphertext), sigEd, sigMl, otherPub); err == nil {
		t.Error("verification under wrong public key — expected failure")
	}
}

func TestVerifyTEEFileSignaturesDomainSeparation(t *testing.T) {
	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}
	ciphertext := bytes.Repeat([]byte{0x42}, 1024)
	sigEd, sigMl, err := SignFileBytes(bytes.NewReader(ciphertext), priv)
	if err != nil {
		t.Fatalf("SignFileBytes: %v", err)
	}
	if err := VerifyTEEFileSignatures(bytes.NewReader(ciphertext), sigEd, sigMl, pub); err == nil {
		t.Error("owner sig verified as TEE sig — domain separation broken")
	}
}

func TestEncryptDecryptSigningPrivateKeys(t *testing.T) {
	_, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}
	pdk := make([]byte, KeySize)
	for i := range pdk {
		pdk[i] = byte(i)
	}
	enc, err := EncryptSigningPrivateKeys(priv, pdk)
	if err != nil {
		t.Fatalf("EncryptSigningPrivateKeys: %v", err)
	}
	if bytes.Equal(enc.Ed25519Nonce, enc.MldsaNonce) {
		t.Error("ed25519 and mldsa nonces are identical — should be independent")
	}
	dec, err := DecryptSigningPrivateKeys(enc, pdk)
	if err != nil {
		t.Fatalf("DecryptSigningPrivateKeys: %v", err)
	}
	if !bytes.Equal(dec.Ed25519, priv.Ed25519) {
		t.Error("ed25519 sk round-trip mismatch")
	}
	if !bytes.Equal(dec.Mldsa, priv.Mldsa) {
		t.Error("mldsa sk round-trip mismatch")
	}

	wrong := make([]byte, KeySize)
	if _, err := DecryptSigningPrivateKeys(enc, wrong); err == nil {
		t.Error("decryption under wrong PDK — expected failure")
	}
}
