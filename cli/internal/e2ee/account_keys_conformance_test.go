package e2ee

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"testing"
	"time"

	"pigcloud/internal/crypto"
)

const accountKeysVectorPassword = "pigcloud account keys v1 | pörk"

type accountWrapRow struct {
	Field string `json:"field"`
	Nonce string `json:"nonce"`
	Plain string `json:"plain"`
	Key   string `json:"key"`
}

var accountWraps = []accountWrapRow{
	{"encrypted_private_key", "private_key_nonce", "x25519_sk", "pdk"},
	{"encrypted_private_key_kyber", "private_key_kyber_nonce", "mlkem_seed", "pdk"},
	{"recovery_encrypted_key", "recovery_key_nonce", "recovery_key", "x25519_sk"},
	{"recovery_private_key_encrypted", "recovery_private_key_nonce", "x25519_sk", "recovery_key"},
	{"recovery_private_key_kyber_encrypted", "recovery_private_key_kyber_nonce", "mlkem_seed", "recovery_key"},
	{"encrypted_signing_private_key_ed25519", "signing_private_key_ed25519_nonce", "ed25519_sk", "pdk"},
	{"encrypted_signing_private_key_mldsa", "signing_private_key_mldsa_nonce", "mldsa_sk", "pdk"},
	{"recovery_signing_private_key_ed25519_encrypted", "recovery_signing_private_key_ed25519_nonce", "ed25519_sk", "recovery_key"},
	{"recovery_signing_private_key_mldsa_encrypted", "recovery_signing_private_key_mldsa_nonce", "mldsa_sk", "recovery_key"},
}

type accountKeysVector struct {
	VectorKind     string            `json:"vector_kind"`
	SpecVersion    int               `json:"spec_version"`
	Description    string            `json:"description"`
	Generator      map[string]string `json:"generator"`
	Password       string            `json:"password"`
	RecoveryKeyB64 string            `json:"recovery_key_b64"`
	Wraps          []accountWrapRow  `json:"wraps"`
	Fields         map[string]string `json:"fields"`
}

func accountKeysVectorPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "vectors", "account_keys_v1.json")
}

func loadAccountKeysVector(t *testing.T) accountKeysVector {
	t.Helper()
	raw, err := os.ReadFile(accountKeysVectorPath())
	if err != nil {
		t.Fatalf("read vector: %v\nrun PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateAccountKeysVector ./internal/e2ee/ to create it", err)
	}
	var v accountKeysVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	if v.VectorKind != "account_keys_v1" || len(v.Wraps) == 0 {
		t.Fatalf("unexpected vector %q with %d wraps", v.VectorKind, len(v.Wraps))
	}
	return v
}

func checkAccountKeys(t *testing.T, fields map[string]string, password string, wraps []accountWrapRow, recoveryKey []byte) {
	t.Helper()
	field := func(name string) []byte {
		b, err := base64.StdEncoding.DecodeString(fields[name])
		if err != nil || len(b) == 0 {
			t.Fatalf("field %s missing or not base64", name)
		}
		return b
	}
	ops, errOps := strconv.ParseUint(fields["kdf_ops_limit"], 10, 32)
	mem, errMem := strconv.ParseUint(fields["kdf_mem_limit"], 10, 32)
	if errOps != nil || errMem != nil {
		t.Fatalf("kdf limits not integers: %q %q", fields["kdf_ops_limit"], fields["kdf_mem_limit"])
	}
	secrets := map[string][]byte{"pdk": crypto.DeriveKey([]byte(password), field("kdf_salt"), uint32(ops), uint32(mem))}
	opened := make([]bool, len(wraps))
	for progress := true; progress; {
		progress = false
		for i, w := range wraps {
			key, ok := secrets[w.Key]
			if opened[i] || !ok {
				continue
			}
			plain, err := crypto.DecryptWithKey(field(w.Field), field(w.Nonce), key)
			if err != nil {
				t.Fatalf("%s does not open under %s: %v", w.Field, w.Key, err)
			}
			if prev, seen := secrets[w.Plain]; seen && !bytes.Equal(prev, plain) {
				t.Fatalf("%s holds a different %s than an earlier wrap", w.Field, w.Plain)
			}
			secrets[w.Plain] = plain
			opened[i], progress = true, true
		}
	}
	for i, w := range wraps {
		if !opened[i] {
			t.Fatalf("%s: nothing opened its key %s", w.Field, w.Key)
		}
	}
	if !bytes.Equal(secrets["recovery_key"], recoveryKey) {
		t.Fatal("the recovery key shown to the user is not the one the account stores")
	}

	var x [32]byte
	copy(x[:], secrets["x25519_sk"])
	pub, err := crypto.DeriveHybridPublic(&crypto.PrivateKeySet{X25519: x, Kyber: secrets["mlkem_seed"]})
	if err != nil {
		t.Fatalf("derive hybrid public: %v", err)
	}
	signPub, err := crypto.DeriveSigningPublic(&crypto.SigningPrivateKeySet{Ed25519: secrets["ed25519_sk"], Mldsa: secrets["mldsa_sk"]})
	if err != nil {
		t.Fatalf("derive signing public: %v", err)
	}
	for name, want := range map[string][]byte{
		"public_key":                 pub.X25519[:],
		"public_key_kyber":           pub.Kyber,
		"signing_public_key_ed25519": signPub.Ed25519[:],
		"signing_public_key_mldsa":   signPub.Mldsa,
	} {
		if !bytes.Equal(field(name), want) {
			t.Fatalf("%s does not match the key derived from its private half", name)
		}
	}
	var blob struct {
		V     int    `json:"v"`
		SigEd string `json:"sig_ed"`
		SigMl string `json:"sig_ml"`
	}
	if err := json.Unmarshal(field("key_bundle_sig"), &blob); err != nil || blob.V != 1 {
		t.Fatalf("key_bundle_sig is not a v1 blob: %v", err)
	}
	sigEd, errEd := base64.StdEncoding.DecodeString(blob.SigEd)
	sigMl, errMl := base64.StdEncoding.DecodeString(blob.SigMl)
	bundle := &crypto.KeyBundle{X25519: pub.X25519[:], Kyber: pub.Kyber, Ed25519: signPub.Ed25519[:], Mldsa: signPub.Mldsa}
	if errEd != nil || errMl != nil || !crypto.VerifyKeyBundle(bundle, sigEd, sigMl) {
		t.Fatal("key_bundle_sig does not verify over the published keys")
	}
}

func TestAccountKeysVectorOpensInGo(t *testing.T) {
	v := loadAccountKeysVector(t)
	recoveryKey, err := base64.StdEncoding.DecodeString(v.RecoveryKeyB64)
	if err != nil {
		t.Fatalf("recovery key: %v", err)
	}
	checkAccountKeys(t, v.Fields, v.Password, v.Wraps, recoveryKey)
}

func TestNewAccountKeysEmitsTheVectorFieldMap(t *testing.T) {
	v := loadAccountKeysVector(t)
	keys, err := NewAccountKeys([]byte(v.Password))
	if err != nil {
		t.Fatalf("NewAccountKeys: %v", err)
	}
	if got, want := slices.Sorted(maps.Keys(keys.Params)), slices.Sorted(maps.Keys(v.Fields)); !slices.Equal(got, want) {
		t.Fatalf("e2ee_setup fields drifted from the vector:\n got %v\nwant %v", got, want)
	}
	checkAccountKeys(t, keys.Params, v.Password, v.Wraps, keys.RecoveryKey)
}

func TestGenerateAccountKeysVector(t *testing.T) {
	if os.Getenv("PIGCLOUD_GEN_VECTORS") != "1" {
		t.Skip("vector generation; set PIGCLOUD_GEN_VECTORS=1 to regenerate the fixture")
	}
	keys, err := NewAccountKeys([]byte(accountKeysVectorPassword))
	if err != nil {
		t.Fatalf("NewAccountKeys: %v", err)
	}
	v := accountKeysVector{
		VectorKind:  "account_keys_v1",
		SpecVersion: 1,
		Description: "The user_encryption_keys column map a client sends at first key setup. Each wraps row is XChaCha20-Poly1305 (no AD) of secret `plain` under secret `key`; pdk is Argon2id(password, kdf_salt, kdf_ops_limit, kdf_mem_limit). A conforming client opens every row, reads one value per secret, derives the four published keys from the opened privates and verifies key_bundle_sig. Clients check their own fresh setup output against the same rows and field set.",
		Generator: map[string]string{
			"impl":         "go",
			"package":      "pigcloud/internal/e2ee",
			"function":     "NewAccountKeys",
			"tool":         "cli/internal/e2ee/account_keys_conformance_test.go (PIGCLOUD_GEN_VECTORS=1 go test -run TestGenerateAccountKeysVector)",
			"generated_at": time.Now().UTC().Format(time.RFC3339),
		},
		Password:       accountKeysVectorPassword,
		RecoveryKeyB64: base64.StdEncoding.EncodeToString(keys.RecoveryKey),
		Wraps:          accountWraps,
		Fields:         keys.Params,
	}
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(accountKeysVectorPath(), append(body, '\n'), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
