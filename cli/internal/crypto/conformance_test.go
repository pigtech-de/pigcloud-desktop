package crypto

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type vectorFile struct {
	VectorKind    string        `json:"vector_kind"`
	SpecVersion   int           `json:"spec_version"`
	KDFInfo       string        `json:"kdf_info"`
	Description   string        `json:"description"`
	Generator     generatorMeta `json:"generator"`
	Recipient     recipientKeys `json:"recipient"`
	PlaintextB64  string        `json:"plaintext_b64"`
	SealedBlobB64 string        `json:"sealed_blob_b64"`
	Layout        hybridLayout  `json:"layout"`
}

type generatorMeta struct {
	Impl        string `json:"impl"`
	Package     string `json:"package"`
	Function    string `json:"function"`
	Tool        string `json:"tool"`
	GeneratedAt string `json:"generated_at"`
}

type recipientKeys struct {
	X25519PkB64  string `json:"x25519_pk_b64"`
	X25519SkB64  string `json:"x25519_sk_b64"`
	MLKemPkB64   string `json:"mlkem_pk_b64"`
	MLKemSeedB64 string `json:"mlkem_seed_b64"`
}

type hybridLayout struct {
	HeaderSize        int `json:"header_size"`
	EphX25519PKOffset int `json:"ephemeral_x25519_pk_offset"`
	EphX25519PKSize   int `json:"ephemeral_x25519_pk_size"`
	MLKemCTOffset     int `json:"mlkem_ciphertext_offset"`
	MLKemCTSize       int `json:"mlkem_ciphertext_size"`
	NonceOffset       int `json:"xchacha20_nonce_offset"`
	NonceSize         int `json:"xchacha20_nonce_size"`
	AEADCTOffset      int `json:"aead_ciphertext_offset"`
}

func TestConformance_HybridSealV1(t *testing.T) {
	path := vectorPath(t, "hybrid_seal_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateHybridSealVector to create it", path, err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "hybrid_seal_v1" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if v.KDFInfo != HybridKDFInfo {
		t.Fatalf("kdf_info mismatch: fixture=%q this impl=%q", v.KDFInfo, HybridKDFInfo)
	}

	priv := &PrivateKeySet{
		X25519: decode32(t, "x25519_sk", v.Recipient.X25519SkB64),
		Kyber:  decodeB64(t, "mlkem_seed", v.Recipient.MLKemSeedB64),
	}
	defer priv.Zero()

	sealed := decodeB64(t, "sealed_blob", v.SealedBlobB64)
	wantPlaintext := decodeB64(t, "plaintext", v.PlaintextB64)

	gotPlaintext, err := HybridUnseal(sealed, priv)
	if err != nil {
		t.Fatalf("HybridUnseal failed — impl diverges from fixture: %v", err)
	}
	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Fatalf("plaintext mismatch — impl unseals but produces different bytes\n  got:  %x\n  want: %x", gotPlaintext, wantPlaintext)
	}
}

type chatMessageVector struct {
	VectorKind    string        `json:"vector_kind"`
	SpecVersion   int           `json:"spec_version"`
	Description   string        `json:"description"`
	Generator     generatorMeta `json:"generator"`
	DataKeyB64    string        `json:"data_key_b64"`
	NonceB64      string        `json:"nonce_b64"`
	PlaintextB64  string        `json:"plaintext_b64"`
	CiphertextB64 string        `json:"ciphertext_b64"`
}

func TestConformance_ChatMessageV1(t *testing.T) {
	path := vectorPath(t, "chat_message_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateChatMessageVector to create it", path, err)
	}
	var v chatMessageVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "chat_message_v1" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}

	dataKey := decodeB64(t, "data_key", v.DataKeyB64)
	nonce := decodeB64(t, "nonce", v.NonceB64)
	ciphertext := decodeB64(t, "ciphertext", v.CiphertextB64)
	wantPlaintext := decodeB64(t, "plaintext", v.PlaintextB64)

	gotPlaintext, err := DecryptMessage(ciphertext, nonce, dataKey)
	if err != nil {
		t.Fatalf("DecryptMessage failed — chat body cipher diverges from fixture: %v", err)
	}
	if !bytes.Equal(gotPlaintext, wantPlaintext) {
		t.Fatalf("plaintext mismatch — decrypts but produces different bytes\n  got:  %x\n  want: %x", gotPlaintext, wantPlaintext)
	}
}

type chunkedPlaintextSpec struct {
	Pattern   string `json:"pattern"`
	Size      int    `json:"size"`
	SHA256Hex string `json:"sha256_hex"`
}

type chunkedMetadata struct {
	Version         int    `json:"version"`
	NonceB64        string `json:"nonce_b64"`
	ChunkSize       int    `json:"chunk_size"`
	Chunks          int    `json:"chunks"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
	PlaintextSize   int64  `json:"plaintext_size"`
	MetadataMAC     string `json:"metadata_mac"`
}

type chunkedFileVector struct {
	VectorKind       string               `json:"vector_kind"`
	SpecVersion      int                  `json:"spec_version"`
	Description      string               `json:"description"`
	Generator        generatorMeta        `json:"generator"`
	Recipient        recipientKeys        `json:"recipient"`
	DataKeyB64       string               `json:"data_key_b64"`
	SealedDataKeyB64 string               `json:"sealed_data_key_b64"`
	Plaintext        chunkedPlaintextSpec `json:"plaintext"`
	CiphertextB64    string               `json:"ciphertext_b64"`
	Metadata         chunkedMetadata      `json:"metadata"`
}

type nameTokenPrivateKey struct {
	X25519SkB64  string `json:"x25519_sk_b64"`
	MLKemSeedB64 string `json:"mlkem_seed_b64"`
}

type nameTokenCase struct {
	Path           string `json:"path"`
	TokenHex       string `json:"token_hex"`
	LegacyTokenHex string `json:"legacy_token_hex,omitempty"`
}

type nameTokenVector struct {
	VectorKind     string              `json:"vector_kind"`
	SpecVersion    int                 `json:"spec_version"`
	NameKeyContext string              `json:"name_key_context"`
	Description    string              `json:"description"`
	Generator      generatorMeta       `json:"generator"`
	PrivateKey     nameTokenPrivateKey `json:"private_key"`
	NameKeyHex     string              `json:"name_key_hex"`
	Cases          []nameTokenCase     `json:"cases"`
}

type signatureDomains struct {
	Owner string `json:"owner"`
	TEE   string `json:"tee"`
}

type signaturePublicKeys struct {
	Ed25519B64 string `json:"ed25519_b64"`
	Mldsa44B64 string `json:"mldsa44_b64"`
}

type signaturePair struct {
	SigEd25519B64 string `json:"sig_ed25519_b64"`
	SigMldsa44B64 string `json:"sig_mldsa44_b64"`
}

type fileSignatureVector struct {
	VectorKind          string              `json:"vector_kind"`
	SpecVersion         int                 `json:"spec_version"`
	Description         string              `json:"description"`
	Generator           generatorMeta       `json:"generator"`
	Domains             signatureDomains    `json:"domains"`
	SigningPub          signaturePublicKeys `json:"signing_pub"`
	CiphertextB64       string              `json:"ciphertext_b64"`
	CiphertextSHA256Hex string              `json:"ciphertext_sha256_hex"`
	Owner               signaturePair       `json:"owner"`
	TEE                 signaturePair       `json:"tee"`
}

type pdkKdfParams struct {
	Algorithm     string `json:"algorithm"`
	SaltB64       string `json:"salt_b64"`
	OpsLimit      uint32 `json:"ops_limit"`
	MemLimitBytes uint32 `json:"mem_limit_bytes"`
	KeySize       int    `json:"key_size"`
}

type pdkWrappedKey struct {
	X25519CiphertextB64 string `json:"x25519_ciphertext_b64"`
	X25519NonceB64      string `json:"x25519_nonce_b64"`
	KyberCiphertextB64  string `json:"kyber_ciphertext_b64"`
	KyberNonceB64       string `json:"kyber_nonce_b64"`
}

type pdkWrapVector struct {
	VectorKind  string              `json:"vector_kind"`
	SpecVersion int                 `json:"spec_version"`
	Description string              `json:"description"`
	Generator   generatorMeta       `json:"generator"`
	Password    string              `json:"password"`
	KDF         pdkKdfParams        `json:"kdf"`
	PdkB64      string              `json:"pdk_b64"`
	PrivateKey  nameTokenPrivateKey `json:"private_key"`
	Wrapped     pdkWrappedKey       `json:"wrapped"`
}

const pdkVectorPassword = "pigcloud conformance passphrase \U0001F437 2026"

func chunkedVectorPlaintext(size int) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func nameVectorPrivateKeySet() *PrivateKeySet {
	priv := &PrivateKeySet{Kyber: make([]byte, KyberSeedSize)}
	for i := range priv.X25519 {
		priv.X25519[i] = byte(i + 1)
	}
	for i := range priv.Kyber {
		priv.Kyber[i] = byte(0x80 + i)
	}
	return priv
}

func pdkVectorPrivateKeySet() *PrivateKeySet {
	priv := &PrivateKeySet{Kyber: make([]byte, KyberSeedSize)}
	for i := range priv.X25519 {
		priv.X25519[i] = byte(0x40 + i)
	}
	for i := range priv.Kyber {
		priv.Kyber[i] = byte(i*5 + 1)
	}
	return priv
}

func bytesReader(b []byte) *bytes.Reader {
	return bytes.NewReader(b)
}

func TestConformance_ChunkedFileV1(t *testing.T) {
	path := vectorPath(t, "chunked_file_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateChunkedFileVector to create it", path, err)
	}
	var v chunkedFileVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "chunked_file_v1" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if v.Metadata.ChunkSize != ChunkSize {
		t.Fatalf("fixture chunk_size=%d, production ChunkSize=%d", v.Metadata.ChunkSize, ChunkSize)
	}

	dataKey := decodeB64(t, "data_key", v.DataKeyB64)
	ciphertext := decodeB64(t, "ciphertext", v.CiphertextB64)
	wantPlaintext := chunkedVectorPlaintext(v.Plaintext.Size)

	priv := &PrivateKeySet{
		X25519: decode32(t, "x25519_sk", v.Recipient.X25519SkB64),
		Kyber:  decodeB64(t, "mlkem_seed", v.Recipient.MLKemSeedB64),
	}
	defer priv.Zero()
	unsealed, err := UnsealDataKey(decodeB64(t, "sealed_data_key", v.SealedDataKeyB64), priv)
	if err != nil {
		t.Fatalf("UnsealDataKey failed — hybrid seal diverges from fixture: %v", err)
	}
	if !bytes.Equal(unsealed, dataKey) {
		t.Fatalf("unsealed data key mismatch")
	}

	meta := &EncryptionMetadata{
		Version:         v.Metadata.Version,
		Nonce:           decodeB64(t, "nonce", v.Metadata.NonceB64),
		ChunkSize:       v.Metadata.ChunkSize,
		Chunks:          v.Metadata.Chunks,
		PlaintextSHA256: v.Metadata.PlaintextSHA256,
		PlaintextSize:   v.Metadata.PlaintextSize,
		MetadataMAC:     v.Metadata.MetadataMAC,
	}
	got, err := DecryptBytes(ciphertext, dataKey, meta)
	if err != nil {
		t.Fatalf("DecryptBytes failed — chunked AEAD diverges from fixture: %v", err)
	}
	if !bytes.Equal(got, wantPlaintext) {
		t.Fatalf("plaintext mismatch — decrypts but produces different bytes (len got=%d want=%d)", len(got), len(wantPlaintext))
	}

	mac, err := ComputeMetadataMAC(dataKey, meta)
	if err != nil {
		t.Fatalf("ComputeMetadataMAC: %v", err)
	}
	if mac != v.Metadata.MetadataMAC {
		t.Fatalf("metadata MAC mismatch\n  got:  %s\n  want: %s", mac, v.Metadata.MetadataMAC)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[len(tampered)/2] ^= 0x01
	if _, err := DecryptBytes(tampered, dataKey, meta); err == nil {
		t.Fatalf("tampered ciphertext decrypted — AEAD not enforced")
	}
}

func TestConformance_NameTokenV1(t *testing.T) {
	path := vectorPath(t, "name_token_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateNameTokenVector to create it", path, err)
	}
	var v nameTokenVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "name_token_v1" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if v.NameKeyContext != nameKeyContext {
		t.Fatalf("name key context mismatch: fixture=%q this impl=%q", v.NameKeyContext, nameKeyContext)
	}

	priv := &PrivateKeySet{
		X25519: decode32(t, "x25519_sk", v.PrivateKey.X25519SkB64),
		Kyber:  decodeB64(t, "mlkem_seed", v.PrivateKey.MLKemSeedB64),
	}
	nameKey, err := DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}
	if hex.EncodeToString(nameKey) != v.NameKeyHex {
		t.Fatalf("name key mismatch\n  got:  %x\n  want: %s", nameKey, v.NameKeyHex)
	}

	legacyCases := 0
	for _, c := range v.Cases {
		token, err := ComputePathToken(nameKey, c.Path)
		if err != nil {
			t.Fatalf("ComputePathToken(%q): %v", c.Path, err)
		}
		if hex.EncodeToString(token) != c.TokenHex {
			t.Errorf("path token mismatch for %q\n  got:  %x\n  want: %s", c.Path, token, c.TokenHex)
		}

		needsLegacy := PathTokenNeedsLegacy(c.Path)
		if needsLegacy != (c.LegacyTokenHex != "") {
			t.Errorf("legacy-token presence mismatch for %q: PathTokenNeedsLegacy=%v fixture legacy present=%v", c.Path, needsLegacy, c.LegacyTokenHex != "")
		}
		if c.LegacyTokenHex != "" {
			legacyCases++
			legacy, err := ComputePathTokenLegacy(nameKey, c.Path)
			if err != nil {
				t.Fatalf("ComputePathTokenLegacy(%q): %v", c.Path, err)
			}
			if hex.EncodeToString(legacy) != c.LegacyTokenHex {
				t.Errorf("legacy path token mismatch for %q\n  got:  %x\n  want: %s", c.Path, legacy, c.LegacyTokenHex)
			}
			if hex.EncodeToString(legacy) == c.TokenHex {
				t.Errorf("legacy token equals canonical for %q; case should not carry a legacy token", c.Path)
			}
		}
	}
	if legacyCases == 0 {
		t.Error("fixture pins no legacy fallback cases; expected at least the U+0130 and word-final Σ paths")
	}
}

func TestConformance_FileSignatureV1(t *testing.T) {
	path := vectorPath(t, "file_signature_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateFileSignatureVector to create it", path, err)
	}
	var v fileSignatureVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "file_signature_v1" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if v.Domains.Owner != SignatureDomain || v.Domains.TEE != TEESignatureDomain {
		t.Fatalf("domain mismatch: fixture owner=%q tee=%q, impl owner=%q tee=%q",
			v.Domains.Owner, v.Domains.TEE, SignatureDomain, TEESignatureDomain)
	}

	pub := &SigningPublicKeySet{
		Ed25519: decode32(t, "ed25519_pk", v.SigningPub.Ed25519B64),
		Mldsa:   decodeB64(t, "mldsa44_pk", v.SigningPub.Mldsa44B64),
	}
	ciphertext := decodeB64(t, "ciphertext", v.CiphertextB64)
	ownerEd := decodeB64(t, "owner sig_ed25519", v.Owner.SigEd25519B64)
	ownerMl := decodeB64(t, "owner sig_mldsa44", v.Owner.SigMldsa44B64)
	teeEd := decodeB64(t, "tee sig_ed25519", v.TEE.SigEd25519B64)
	teeMl := decodeB64(t, "tee sig_mldsa44", v.TEE.SigMldsa44B64)

	if err := VerifyFileSignatures(bytes.NewReader(ciphertext), ownerEd, ownerMl, pub); err != nil {
		t.Fatalf("VerifyFileSignatures failed — owner-domain signatures diverge from fixture: %v", err)
	}
	if err := VerifyTEEFileSignatures(bytes.NewReader(ciphertext), teeEd, teeMl, pub); err != nil {
		t.Fatalf("VerifyTEEFileSignatures failed — TEE-domain signatures diverge from fixture: %v", err)
	}

	if err := VerifyTEEFileSignatures(bytes.NewReader(ciphertext), ownerEd, ownerMl, pub); err == nil {
		t.Fatalf("owner-domain signatures verified under the TEE domain — domain separation broken")
	}
	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0x01
	if err := VerifyFileSignatures(bytes.NewReader(tampered), ownerEd, ownerMl, pub); err == nil {
		t.Fatalf("tampered ciphertext verified — signature not bound to bytes")
	}
}

func TestConformance_PdkWrapV1(t *testing.T) {
	path := vectorPath(t, "pdk_argon2id_v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGeneratePdkWrapVector to create it", path, err)
	}
	var v pdkWrapVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	if v.VectorKind != "pdk_argon2id_v1" {
		t.Fatalf("unexpected vector_kind=%q", v.VectorKind)
	}
	if v.KDF.OpsLimit != KDFOpsLimit || v.KDF.MemLimitBytes != KDFMemLimitBytes {
		t.Fatalf("KDF params drifted from production defaults: fixture ops=%d mem=%d, impl ops=%d mem=%d",
			v.KDF.OpsLimit, v.KDF.MemLimitBytes, KDFOpsLimit, KDFMemLimitBytes)
	}

	salt := decodeB64(t, "salt", v.KDF.SaltB64)
	wantPdk := decodeB64(t, "pdk", v.PdkB64)
	pdk := DeriveKey([]byte(v.Password), salt, v.KDF.OpsLimit, v.KDF.MemLimitBytes)
	if !bytes.Equal(pdk, wantPdk) {
		t.Fatalf("PDK mismatch — Argon2id derivation diverges from fixture")
	}

	enc := &EncryptedHybridPrivateKey{
		X25519Ciphertext: decodeB64(t, "x25519_ct", v.Wrapped.X25519CiphertextB64),
		X25519Nonce:      decodeB64(t, "x25519_nonce", v.Wrapped.X25519NonceB64),
		KyberCiphertext:  decodeB64(t, "kyber_ct", v.Wrapped.KyberCiphertextB64),
		KyberNonce:       decodeB64(t, "kyber_nonce", v.Wrapped.KyberNonceB64),
		Salt:             salt,
		OpsLimit:         v.KDF.OpsLimit,
		MemLimit:         v.KDF.MemLimitBytes,
	}
	priv, err := DecryptHybridPrivateKeyWithRawKey(enc, pdk)
	if err != nil {
		t.Fatalf("DecryptHybridPrivateKeyWithRawKey failed — wrap construction diverges from fixture: %v", err)
	}
	defer priv.Zero()

	wantX := decode32(t, "x25519_sk", v.PrivateKey.X25519SkB64)
	wantSeed := decodeB64(t, "mlkem_seed", v.PrivateKey.MLKemSeedB64)
	if priv.X25519 != wantX {
		t.Fatalf("unwrapped x25519 sk mismatch")
	}
	if !bytes.Equal(priv.Kyber, wantSeed) {
		t.Fatalf("unwrapped mlkem seed mismatch")
	}
}

func vectorPath(t *testing.T, name string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", name)
}

func decodeB64(t *testing.T, label, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64 decode %s: %v", label, err)
	}
	return b
}

func decode32(t *testing.T, label, s string) [32]byte {
	t.Helper()
	b := decodeB64(t, label, s)
	if len(b) != 32 {
		t.Fatalf("%s: want 32 bytes, got %d", label, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}
