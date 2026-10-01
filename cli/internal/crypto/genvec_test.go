package crypto

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestGenerateHybridSealVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer priv.Zero()

	plaintext := []byte("pigcloud-hybrid-seal-v2 | conformance vector #1 | UTF-8: pörk pîë \xf0\x9f\x90\xb7")

	sealed, err := HybridSeal(plaintext, pub)
	if err != nil {
		t.Fatalf("HybridSeal: %v", err)
	}
	if len(sealed) < 1144+16 {
		t.Fatalf("sealed blob too short: %d", len(sealed))
	}

	v := vectorFile{
		VectorKind:  "hybrid_seal_v1",
		SpecVersion: 2,
		KDFInfo:     HybridKDFInfo,
		Description: "Hybrid X25519+ML-KEM-768 sealed blob. Each conforming impl must HybridUnseal(sealed_blob_b64, recipient.sk_b64+seed_b64) and recover plaintext_b64 byte-for-byte.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "HybridSeal",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateHybridSealVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Recipient: recipientKeys{
			X25519PkB64:  base64.StdEncoding.EncodeToString(pub.X25519[:]),
			X25519SkB64:  base64.StdEncoding.EncodeToString(priv.X25519[:]),
			MLKemPkB64:   base64.StdEncoding.EncodeToString(pub.Kyber),
			MLKemSeedB64: base64.StdEncoding.EncodeToString(priv.Kyber),
		},
		PlaintextB64:  base64.StdEncoding.EncodeToString(plaintext),
		SealedBlobB64: base64.StdEncoding.EncodeToString(sealed),
		Layout: hybridLayout{
			HeaderSize:        1144,
			EphX25519PKOffset: 0,
			EphX25519PKSize:   32,
			MLKemCTOffset:     32,
			MLKemCTSize:       1088,
			NonceOffset:       1120,
			NonceSize:         24,
			AEADCTOffset:      1144,
		},
	}

	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body = append(body, '\n')

	dst := vectorPath(t, "hybrid_seal_v1.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(body))
}

func TestGenerateDisplayNamePadVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer priv.Zero()

	cases := []struct {
		label  string
		name   string
		legacy bool
		note   string
	}{
		{label: "short-ascii", name: "report.pdf", note: "small name lands in the 64 bucket"},
		{label: "empty-name", name: "", note: "empty name still pads to the 64 bucket"},
		{label: "fits-64-exactly", name: strings.Repeat("a", 56) + ".txt", note: "header + 60 name bytes exactly fill the 64 bucket"},
		{label: "spills-to-128", name: strings.Repeat("a", 57) + ".txt", note: "one byte past the 64 bucket"},
		{label: "multibyte", name: "pörk pîë 🐷 名前.txt", note: "bucket chosen by UTF-8 byte length, not rune count"},
		{label: "mid-512", name: strings.Repeat("б", 150), note: "300 name bytes land in the 512 bucket"},
		{label: "max-padded", name: strings.Repeat("a", 884), note: "largest name the 888 bucket holds"},
		{label: "oversize-raw", name: strings.Repeat("a", 885), note: "past the top bucket: sealed raw, same shape as legacy"},
		{label: "legacy-raw", name: "pre-padding name.txt", legacy: true, note: "sealed without the pad envelope; must unseal unchanged"},
	}

	v := displayNamePadVectorFile{
		VectorKind:  "display_name_pad",
		SpecVersion: 1,
		Description: "Bucket-padded display-name plaintexts under the hybrid seal. Each conforming impl must UnsealDisplayName every case to name_b64, open each blob to padded_plaintext_len plaintext bytes, and SealDisplayName each non-legacy name to seal_overhead_bytes + padded_plaintext_len total bytes.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "SealDisplayName",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateDisplayNamePadVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Recipient: recipientKeys{
			X25519PkB64:  base64.StdEncoding.EncodeToString(pub.X25519[:]),
			X25519SkB64:  base64.StdEncoding.EncodeToString(priv.X25519[:]),
			MLKemPkB64:   base64.StdEncoding.EncodeToString(pub.Kyber),
			MLKemSeedB64: base64.StdEncoding.EncodeToString(priv.Kyber),
		},
		SealOverheadBytes: 1160,
		HeaderBytes:       displayNamePadHeader,
		Buckets:           displayNamePadBuckets[:],
	}
	for _, c := range cases {
		var sealed []byte
		if c.legacy {
			sealed, err = HybridSeal([]byte(c.name), pub)
		} else {
			sealed, err = SealDisplayName(c.name, pub)
		}
		if err != nil {
			t.Fatalf("%s: seal: %v", c.label, err)
		}
		paddedLen := len(c.name)
		if !c.legacy {
			paddedLen = len(padDisplayName([]byte(c.name)))
		}
		v.Cases = append(v.Cases, displayNamePadCase{
			Label:              c.label,
			Note:               c.note,
			NameB64:            base64.StdEncoding.EncodeToString([]byte(c.name)),
			SealedBlobB64:      base64.StdEncoding.EncodeToString(sealed),
			PaddedPlaintextLen: paddedLen,
			Legacy:             c.legacy,
		})
	}

	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body = append(body, '\n')

	dst := vectorPath(t, "display_name_pad_v1.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(body))
}

func TestGenerateParentRefVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer priv.Zero()
	parentKey, err := DeriveParentKey(priv)
	if err != nil {
		t.Fatalf("DeriveParentKey: %v", err)
	}

	parentID, _ := hex.DecodeString("aabbccddeeff00112233445566778899")
	nodeID, _ := hex.DecodeString("99887766554433221100ffeeddccbbaa")
	rootNodeID, _ := hex.DecodeString("0102030405060708090a0b0c0d0e0f10")

	type refCase struct {
		label  string
		parent []byte
		node   []byte
		seal   func() ([]byte, error)
	}
	cases := []refCase{
		{"own-nested", parentID, nodeID, func() ([]byte, error) { return SealParentRef(parentID, nodeID, parentKey) }},
		{"own-root", nil, rootNodeID, func() ([]byte, error) { return SealParentRef(nil, rootNodeID, parentKey) }},
		{"foreign-nested", parentID, nodeID, func() ([]byte, error) { return SealParentRefForRecipient(parentID, nodeID, pub) }},
		{"foreign-root", nil, rootNodeID, func() ([]byte, error) { return SealParentRefForRecipient(nil, rootNodeID, pub) }},
	}

	v := parentRefVectorFile{
		VectorKind:  "parent_ref",
		SpecVersion: 1,
		Description: "Sealed parent references, both envelope versions. Each conforming impl must derive the same parent key from the private set, open every case to parent_id_hex (empty = root), and refuse a mismatched node id.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "SealParentRef / SealParentRefForRecipient",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateParentRefVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Recipient: recipientKeys{
			X25519PkB64:  base64.StdEncoding.EncodeToString(pub.X25519[:]),
			X25519SkB64:  base64.StdEncoding.EncodeToString(priv.X25519[:]),
			MLKemPkB64:   base64.StdEncoding.EncodeToString(pub.Kyber),
			MLKemSeedB64: base64.StdEncoding.EncodeToString(priv.Kyber),
		},
		ParentKeyB64:    base64.StdEncoding.EncodeToString(parentKey),
		KeyContext:      parentKeyContext,
		OwnSealedLength: 1 + parentRefNonceSize + parentRefIDSize + 16,
	}
	for _, c := range cases {
		sealed, err := c.seal()
		if err != nil {
			t.Fatalf("%s: seal: %v", c.label, err)
		}
		v.Cases = append(v.Cases, parentRefCase{
			Label:         c.label,
			ParentIDHex:   hex.EncodeToString(c.parent),
			NodeIDHex:     hex.EncodeToString(c.node),
			SealedBlobB64: base64.StdEncoding.EncodeToString(sealed),
		})
	}

	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body = append(body, '\n')

	dst := vectorPath(t, "parent_ref_v1.json")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(body))
}

func TestGenerateChatMessageVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	dataKey := make([]byte, KeySize)
	for i := range dataKey {
		dataKey[i] = byte(i)
	}
	nonce := make([]byte, NonceSize)
	for i := range nonce {
		nonce[i] = byte(0x40 + i)
	}
	plaintext := []byte("pigcloud chat body | web<->CLI XChaCha20-Poly1305 IETF | UTF-8: pörk pîë \xf0\x9f\x90\xb7")

	aead, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		t.Fatalf("NewX: %v", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	v := chatMessageVector{
		VectorKind:  "chat_message_v1",
		SpecVersion: 1,
		Description: "Chat message body cipher (XChaCha20-Poly1305 IETF). Each impl must DecryptMessage(ciphertext_b64, nonce_b64, data_key_b64) and recover plaintext_b64. Guards the CLI<->web chat split (was XSalsa20 secretbox on the CLI).",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "EncryptMessage",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateChatMessageVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		DataKeyB64:    base64.StdEncoding.EncodeToString(dataKey),
		NonceB64:      base64.StdEncoding.EncodeToString(nonce),
		PlaintextB64:  base64.StdEncoding.EncodeToString(plaintext),
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
	}

	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body = append(body, '\n')

	dst := vectorPath(t, "chat_message_v1.json")
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(body))
}

func writeVectorJSON(t *testing.T, name string, v any) {
	t.Helper()
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body = append(body, '\n')
	dst := vectorPath(t, name)
	if err := os.WriteFile(dst, body, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
	t.Logf("wrote %s (%d bytes)", dst, len(body))
}

func TestGenerateChunkedFileVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	dataKey := make([]byte, KeySize)
	for i := range dataKey {
		dataKey[i] = byte(i*7 + 3)
	}
	plaintext := chunkedVectorPlaintext(ChunkSize + 4099)

	dir := t.TempDir()
	inPath := filepath.Join(dir, "plain.bin")
	outPath := filepath.Join(dir, "cipher.bin")
	if err := os.WriteFile(inPath, plaintext, 0o600); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	meta, err := EncryptFile(inPath, outPath, dataKey)
	if err != nil {
		t.Fatalf("EncryptFile: %v", err)
	}
	ciphertext, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}

	pub, priv, err := GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("GenerateHybridKeyPair: %v", err)
	}
	defer priv.Zero()
	sealedKey, err := SealDataKey(dataKey, pub)
	if err != nil {
		t.Fatalf("SealDataKey: %v", err)
	}

	v := chunkedFileVector{
		VectorKind:  "chunked_file_v1",
		SpecVersion: meta.Version,
		Description: "Chunked XChaCha20-Poly1305 file AEAD + metadata MAC. Each impl must decrypt ciphertext_b64 with data_key_b64 (or unseal sealed_data_key_b64 first), recover the pattern plaintext byte-for-byte, and verify metadata.metadata_mac over the canonical array.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "EncryptFile",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateChunkedFileVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Recipient: recipientKeys{
			X25519PkB64:  base64.StdEncoding.EncodeToString(pub.X25519[:]),
			X25519SkB64:  base64.StdEncoding.EncodeToString(priv.X25519[:]),
			MLKemPkB64:   base64.StdEncoding.EncodeToString(pub.Kyber),
			MLKemSeedB64: base64.StdEncoding.EncodeToString(priv.Kyber),
		},
		DataKeyB64:       base64.StdEncoding.EncodeToString(dataKey),
		SealedDataKeyB64: base64.StdEncoding.EncodeToString(sealedKey),
		Plaintext: chunkedPlaintextSpec{
			Pattern:   "byte[i] = i mod 251",
			Size:      len(plaintext),
			SHA256Hex: meta.PlaintextSHA256,
		},
		CiphertextB64: base64.StdEncoding.EncodeToString(ciphertext),
		Metadata: chunkedMetadata{
			Version:         meta.Version,
			NonceB64:        base64.StdEncoding.EncodeToString(meta.Nonce),
			ChunkSize:       meta.ChunkSize,
			Chunks:          meta.Chunks,
			PlaintextSHA256: meta.PlaintextSHA256,
			PlaintextSize:   meta.PlaintextSize,
			MetadataMAC:     meta.MetadataMAC,
		},
	}
	writeVectorJSON(t, "chunked_file_v1.json", v)
}

func TestGenerateNameTokenVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	priv := nameVectorPrivateKeySet()
	nameKey, err := DeriveNameKey(priv)
	if err != nil {
		t.Fatalf("DeriveNameKey: %v", err)
	}

	paths := []string{
		"Documents/Report.PDF",
		"photos/Urlaub 2025/Straße.jpg",
		"GROSS/WEISS.TXT",
		"münchen/Ärger.txt",
		"café/résumé.doc",
		"café/résumé.doc",
		"\U0001F437 pig/\U0001F4C1 files",
		"\\windows\\Style\\Path.txt",
		"//double//slash/",
		"/leading/trailing/",
		"İstanbul/dosya.txt",
		"Diyarbakır/İZMİR.txt",
		"ΟΔΥΣΣΕΑΣ/ΣΟΦΟΣ.txt",
		"Σ ΣΣ Σ.txt",
		"ΕΛΛΑΣ.txt",
		"ΜΆΪΟΣ/Δ.doc",
		"ıstanbul/dosya.txt",
		"Σοφός/Σ.txt",
		"ẞ/scharfes.txt",
		"K/kelvin.txt",
		"АБВ/ГД.txt",
		"Ǆjur/file.txt",
		"äpfel/ÄPFEL.txt",
	}

	cases := make([]nameTokenCase, 0, len(paths))
	for _, p := range paths {
		token, err := ComputePathToken(nameKey, p)
		if err != nil {
			t.Fatalf("ComputePathToken(%q): %v", p, err)
		}
		c := nameTokenCase{Path: p, TokenHex: hex.EncodeToString(token)}
		if PathTokenNeedsLegacy(p) {
			legacyToken, err := ComputePathTokenLegacy(nameKey, p)
			if err != nil {
				t.Fatalf("ComputePathTokenLegacy(%q): %v", p, err)
			}
			c.LegacyTokenHex = hex.EncodeToString(legacyToken)
		}
		cases = append(cases, c)
	}

	v := nameTokenVector{
		VectorKind:     "name_token_v1",
		SpecVersion:    1,
		NameKeyContext: nameKeyContext,
		Description:    "Name-key derivation (BLAKE2b-256 keyed by context over x25519_sk || mlkem_seed) + path-token derivation (BLAKE2b-256 keyed by name key over the normalized path). Each impl must reproduce name_key_hex and every case token_hex. Cases whose canonical and pre-convergence (simple lowercase) normalizers disagree (XLANG-CR-04: U+0130, word-final U+03A3) also carry legacy_token_hex, the token an older client sends as path_tokens_legacy; every impl must reproduce it and produce nothing for unaffected paths.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "DeriveNameKey/ComputePathToken",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateNameTokenVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		PrivateKey: nameTokenPrivateKey{
			X25519SkB64:  base64.StdEncoding.EncodeToString(priv.X25519[:]),
			MLKemSeedB64: base64.StdEncoding.EncodeToString(priv.Kyber),
		},
		NameKeyHex: hex.EncodeToString(nameKey),
		Cases:      cases,
	}
	writeVectorJSON(t, "name_token_v1.json", v)
}

func TestGenerateFileSignatureVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	pub, priv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair: %v", err)
	}
	defer priv.Zero()

	ciphertext := chunkedVectorPlaintext(4096)
	digest := sha256.Sum256(ciphertext)

	ownerEd, ownerMl, err := SignFileBytes(bytesReader(ciphertext), priv)
	if err != nil {
		t.Fatalf("SignFileBytes: %v", err)
	}

	teeInput := signingInput(TEESignatureDomain, digest[:])
	teeEd := ed25519.Sign(priv.Ed25519, teeInput)
	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(priv.Mldsa); err != nil {
		t.Fatalf("mldsa44 priv unmarshal: %v", err)
	}
	teeMl := make([]byte, Mldsa44SigSize)
	if err := mldsa44.SignTo(&mlPriv, teeInput, nil, false, teeMl); err != nil {
		t.Fatalf("mldsa44 sign: %v", err)
	}

	v := fileSignatureVector{
		VectorKind:  "file_signature_v1",
		SpecVersion: 1,
		Description: "Hybrid file signatures (Ed25519 + ML-DSA-44, strict-AND) over domain || sha256(ciphertext). ML-DSA signing may be randomized per impl, so each impl VERIFIES the committed signatures instead of re-signing. Owner and TEE domains carry separate pairs.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "SignFileBytes",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateFileSignatureVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Domains: signatureDomains{
			Owner: SignatureDomain,
			TEE:   TEESignatureDomain,
		},
		SigningPub: signaturePublicKeys{
			Ed25519B64: base64.StdEncoding.EncodeToString(pub.Ed25519[:]),
			Mldsa44B64: base64.StdEncoding.EncodeToString(pub.Mldsa),
		},
		CiphertextB64:       base64.StdEncoding.EncodeToString(ciphertext),
		CiphertextSHA256Hex: hex.EncodeToString(digest[:]),
		Owner: signaturePair{
			SigEd25519B64: base64.StdEncoding.EncodeToString(ownerEd),
			SigMldsa44B64: base64.StdEncoding.EncodeToString(ownerMl),
		},
		TEE: signaturePair{
			SigEd25519B64: base64.StdEncoding.EncodeToString(teeEd),
			SigMldsa44B64: base64.StdEncoding.EncodeToString(teeMl),
		},
	}
	writeVectorJSON(t, "file_signature_v1.json", v)
}

func TestGeneratePdkWrapVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	priv := pdkVectorPrivateKeySet()
	password := pdkVectorPassword

	enc, err := EncryptHybridPrivateKey(priv, []byte(password))
	if err != nil {
		t.Fatalf("EncryptHybridPrivateKey: %v", err)
	}
	pdk := DeriveKey([]byte(password), enc.Salt, enc.OpsLimit, enc.MemLimit)

	v := pdkWrapVector{
		VectorKind:  "pdk_argon2id_v1",
		SpecVersion: 1,
		Description: "Argon2id PDK derivation + private-key wrap (XChaCha20-Poly1305, one fresh nonce per half). Each impl must derive pdk_b64 from the password + kdf params and unwrap both halves to private_key.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "EncryptHybridPrivateKey",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGeneratePdkWrapVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Password: password,
		KDF: pdkKdfParams{
			Algorithm:     "argon2id13",
			SaltB64:       base64.StdEncoding.EncodeToString(enc.Salt),
			OpsLimit:      enc.OpsLimit,
			MemLimitBytes: enc.MemLimit,
			KeySize:       KeySize,
		},
		PdkB64: base64.StdEncoding.EncodeToString(pdk),
		PrivateKey: nameTokenPrivateKey{
			X25519SkB64:  base64.StdEncoding.EncodeToString(priv.X25519[:]),
			MLKemSeedB64: base64.StdEncoding.EncodeToString(priv.Kyber),
		},
		Wrapped: pdkWrappedKey{
			X25519CiphertextB64: base64.StdEncoding.EncodeToString(enc.X25519Ciphertext),
			X25519NonceB64:      base64.StdEncoding.EncodeToString(enc.X25519Nonce),
			KyberCiphertextB64:  base64.StdEncoding.EncodeToString(enc.KyberCiphertext),
			KyberNonceB64:       base64.StdEncoding.EncodeToString(enc.KyberNonce),
		},
	}
	writeVectorJSON(t, "pdk_argon2id_v1.json", v)
}

type signingPkHistoryBlobVec struct {
	V     int      `json:"v"`
	Eds   []string `json:"eds"`
	SigEd string   `json:"sig_ed"`
	SigMl string   `json:"sig_ml"`
}

type signingPkHistoryVector struct {
	VectorKind  string                  `json:"vector_kind"`
	SpecVersion int                     `json:"spec_version"`
	Description string                  `json:"description"`
	Generator   generatorMeta           `json:"generator"`
	Domain      string                  `json:"domain"`
	SigningPub  signaturePublicKeys     `json:"signing_pub"`
	Blob        signingPkHistoryBlobVec `json:"blob"`
}

func TestGenerateSigningPkHistoryVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

	oldPub, oldPriv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair(old): %v", err)
	}
	defer oldPriv.Zero()
	curPub, curPriv, err := GenerateSigningKeyPair()
	if err != nil {
		t.Fatalf("GenerateSigningKeyPair(cur): %v", err)
	}
	defer curPriv.Zero()

	const domain = "pigcloud-signing-pk-history-v1"
	eds := [][]byte{oldPub.Ed25519[:], curPub.Ed25519[:]}
	input := []byte(domain)
	edsB64 := make([]string, 0, len(eds))
	for _, e := range eds {
		input = append(input, e...)
		edsB64 = append(edsB64, base64.StdEncoding.EncodeToString(e))
	}

	sigEd := ed25519.Sign(curPriv.Ed25519, input)
	var mlPriv mldsa44.PrivateKey
	if err := mlPriv.UnmarshalBinary(curPriv.Mldsa); err != nil {
		t.Fatalf("mldsa44 priv unmarshal: %v", err)
	}
	sigMl := make([]byte, Mldsa44SigSize)
	if err := mldsa44.SignTo(&mlPriv, input, nil, false, sigMl); err != nil {
		t.Fatalf("mldsa44 sign: %v", err)
	}

	v := signingPkHistoryVector{
		VectorKind:  "signing_pk_history_v1",
		SpecVersion: 1,
		Description: "Signed signing-PK enrollment history (Ed25519 + ML-DSA-44, strict-AND) over domain || concat(raw ed25519 pubs). Verifiers VERIFY the committed blob against the current signing pubs: a valid blob passes; a blob with a tampered ML-DSA signature MUST be rejected (guards SEC-E2EE-23, the PQ downgrade where only Ed25519 was checked).",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "ed25519.Sign + mldsa44.SignTo",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateSigningPkHistoryVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Domain: domain,
		SigningPub: signaturePublicKeys{
			Ed25519B64: base64.StdEncoding.EncodeToString(curPub.Ed25519[:]),
			Mldsa44B64: base64.StdEncoding.EncodeToString(curPub.Mldsa),
		},
		Blob: signingPkHistoryBlobVec{
			V:     1,
			Eds:   edsB64,
			SigEd: base64.StdEncoding.EncodeToString(sigEd),
			SigMl: base64.StdEncoding.EncodeToString(sigMl),
		},
	}
	writeVectorJSON(t, "signing_pk_history_v1.json", v)
}

type keyBundlePubsVec struct {
	X25519B64  string `json:"x25519_b64"`
	KyberB64   string `json:"kyber_b64"`
	Ed25519B64 string `json:"ed25519_b64"`
	Mldsa44B64 string `json:"mldsa44_b64"`
}

type keyBundleBlobVec struct {
	V     int    `json:"v"`
	SigEd string `json:"sig_ed"`
	SigMl string `json:"sig_ml"`
}

type keyBundleVector struct {
	VectorKind  string           `json:"vector_kind"`
	SpecVersion int              `json:"spec_version"`
	Description string           `json:"description"`
	Generator   generatorMeta    `json:"generator"`
	Domain      string           `json:"domain"`
	Bundle      keyBundlePubsVec `json:"bundle"`
	Blob        keyBundleBlobVec `json:"blob"`
}

func TestGenerateKeyBundleVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}

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

	bundle := &KeyBundle{
		X25519:  kemPub.X25519[:],
		Kyber:   kemPub.Kyber,
		Ed25519: signPub.Ed25519[:],
		Mldsa:   signPub.Mldsa,
	}
	sigEd, sigMl, err := SignKeyBundle(bundle, signPriv)
	if err != nil {
		t.Fatalf("SignKeyBundle: %v", err)
	}

	v := keyBundleVector{
		VectorKind:  "key_bundle_v1",
		SpecVersion: 1,
		Description: "Self-signed published key bundle (Ed25519 + ML-DSA-44, strict-AND) over domain || x25519 || mlkem768 || ed25519 || mldsa44, every field fixed-length. Verifiers VERIFY the bundle against the signing pubs inside it: the committed bundle passes; tampering with either signature, or with any published key, MUST be rejected. This is what stops a server substituting a peer's KEM halves under a signing identity the client already pinned.",
		Generator: generatorMeta{
			Impl:        "go",
			Package:     "pigcloud/internal/crypto",
			Function:    "SignKeyBundle",
			Tool:        "cli/internal/crypto/genvec_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateKeyBundleVector)",
			GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Domain: KeyBundleDomain,
		Bundle: keyBundlePubsVec{
			X25519B64:  base64.StdEncoding.EncodeToString(bundle.X25519),
			KyberB64:   base64.StdEncoding.EncodeToString(bundle.Kyber),
			Ed25519B64: base64.StdEncoding.EncodeToString(bundle.Ed25519),
			Mldsa44B64: base64.StdEncoding.EncodeToString(bundle.Mldsa),
		},
		Blob: keyBundleBlobVec{
			V:     1,
			SigEd: base64.StdEncoding.EncodeToString(sigEd),
			SigMl: base64.StdEncoding.EncodeToString(sigMl),
		},
	}
	writeVectorJSON(t, "key_bundle_v1.json", v)
}
