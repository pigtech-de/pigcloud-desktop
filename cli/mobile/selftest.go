package mobile

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"pigcloud/internal/crypto"
)

const Version = "1"

func BindingVersion() string { return Version }

//go:embed vectors/*.json
var vectors embed.FS

type hybridSealVector struct {
	VectorKind string `json:"vector_kind"`
	KDFInfo    string `json:"kdf_info"`
	Recipient  struct {
		X25519SkB64  string `json:"x25519_sk_b64"`
		MLKemSeedB64 string `json:"mlkem_seed_b64"`
	} `json:"recipient"`
	SealedBlobB64 string `json:"sealed_blob_b64"`
	PlaintextB64  string `json:"plaintext_b64"`
}

type nameTokenVector struct {
	VectorKind string `json:"vector_kind"`
	PrivateKey struct {
		X25519SkB64  string `json:"x25519_sk_b64"`
		MLKemSeedB64 string `json:"mlkem_seed_b64"`
	} `json:"private_key"`
	NameKeyHex string `json:"name_key_hex"`
	Cases      []struct {
		Path           string `json:"path"`
		TokenHex       string `json:"token_hex"`
		LegacyTokenHex string `json:"legacy_token_hex"`
	} `json:"cases"`
}

type pdkVector struct {
	VectorKind string `json:"vector_kind"`
	Password   string `json:"password"`
	KDF        struct {
		SaltB64       string `json:"salt_b64"`
		OpsLimit      uint32 `json:"ops_limit"`
		MemLimitBytes uint32 `json:"mem_limit_bytes"`
	} `json:"kdf"`
	PdkB64 string `json:"pdk_b64"`
}

type selfTestReport struct {
	OK       bool     `json:"ok"`
	Version  string   `json:"version"`
	Families []string `json:"families"`
	Failures []string `json:"failures"`
}

func SelfTest(includeKDF bool) (string, error) {
	report := selfTestReport{Version: Version}

	if err := checkHybridSeal(); err != nil {
		report.Failures = append(report.Failures, err.Error())
	} else {
		report.Families = append(report.Families, "hybrid_seal_v1")
	}

	if err := checkNameTokens(); err != nil {
		report.Failures = append(report.Failures, err.Error())
	} else {
		report.Families = append(report.Families, "name_token_v1")
	}

	if includeKDF {
		if err := checkPdkWrap(); err != nil {
			report.Failures = append(report.Failures, err.Error())
		} else {
			report.Families = append(report.Families, "pdk_argon2id_v1")
		}
	}

	report.OK = len(report.Failures) == 0
	return encodeJSON(report)
}

func loadVector(name string, into any) error {
	raw, err := vectors.ReadFile("vectors/" + name)
	if err != nil {
		return fmt.Errorf("%s: not embedded: %w", name, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s: parse: %w", name, err)
	}
	return nil
}

func checkHybridSeal() error {
	var v hybridSealVector
	if err := loadVector("hybrid_seal_v1.json", &v); err != nil {
		return err
	}
	if v.VectorKind != "hybrid_seal_v1" {
		return fmt.Errorf("hybrid_seal_v1: fixture says vector_kind=%q", v.VectorKind)
	}
	sk, err := decode32(v.Recipient.X25519SkB64)
	if err != nil {
		return fmt.Errorf("hybrid_seal_v1: x25519_sk: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(v.Recipient.MLKemSeedB64)
	if err != nil {
		return fmt.Errorf("hybrid_seal_v1: mlkem_seed: %w", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(v.SealedBlobB64)
	if err != nil {
		return fmt.Errorf("hybrid_seal_v1: sealed_blob: %w", err)
	}
	want, err := base64.StdEncoding.DecodeString(v.PlaintextB64)
	if err != nil {
		return fmt.Errorf("hybrid_seal_v1: plaintext: %w", err)
	}

	priv := &crypto.PrivateKeySet{X25519: sk, Kyber: seed}
	defer priv.Zero()
	got, err := crypto.HybridUnseal(sealed, priv)
	if err != nil {
		return fmt.Errorf("hybrid_seal_v1: HybridUnseal: %w", err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("hybrid_seal_v1: unsealed %d bytes that differ from the fixture", len(got))
	}
	return nil
}

func checkNameTokens() error {
	var v nameTokenVector
	if err := loadVector("name_token_v1.json", &v); err != nil {
		return err
	}
	if v.VectorKind != "name_token_v1" {
		return fmt.Errorf("name_token_v1: fixture says vector_kind=%q", v.VectorKind)
	}
	sk, err := decode32(v.PrivateKey.X25519SkB64)
	if err != nil {
		return fmt.Errorf("name_token_v1: x25519_sk: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(v.PrivateKey.MLKemSeedB64)
	if err != nil {
		return fmt.Errorf("name_token_v1: mlkem_seed: %w", err)
	}
	priv := &crypto.PrivateKeySet{X25519: sk, Kyber: seed}
	defer priv.Zero()

	nameKey, err := crypto.DeriveNameKey(priv)
	if err != nil {
		return fmt.Errorf("name_token_v1: DeriveNameKey: %w", err)
	}
	if hex.EncodeToString(nameKey) != v.NameKeyHex {
		return fmt.Errorf("name_token_v1: derived name key differs from the fixture")
	}
	if len(v.Cases) == 0 {
		return fmt.Errorf("name_token_v1: fixture pins no cases")
	}
	for _, c := range v.Cases {
		token, err := crypto.ComputePathToken(nameKey, c.Path)
		if err != nil {
			return fmt.Errorf("name_token_v1: ComputePathToken(%q): %w", c.Path, err)
		}
		if hex.EncodeToString(token) != c.TokenHex {
			return fmt.Errorf("name_token_v1: token mismatch for %q", c.Path)
		}
		if c.LegacyTokenHex == "" {
			continue
		}
		legacy, err := crypto.ComputePathTokenLegacy(nameKey, c.Path)
		if err != nil {
			return fmt.Errorf("name_token_v1: ComputePathTokenLegacy(%q): %w", c.Path, err)
		}
		if hex.EncodeToString(legacy) != c.LegacyTokenHex {
			return fmt.Errorf("name_token_v1: legacy token mismatch for %q", c.Path)
		}
	}
	return nil
}

func checkPdkWrap() error {
	var v pdkVector
	if err := loadVector("pdk_argon2id_v1.json", &v); err != nil {
		return err
	}
	if v.VectorKind != "pdk_argon2id_v1" {
		return fmt.Errorf("pdk_argon2id_v1: fixture says vector_kind=%q", v.VectorKind)
	}
	salt, err := base64.StdEncoding.DecodeString(v.KDF.SaltB64)
	if err != nil {
		return fmt.Errorf("pdk_argon2id_v1: salt: %w", err)
	}
	want, err := base64.StdEncoding.DecodeString(v.PdkB64)
	if err != nil {
		return fmt.Errorf("pdk_argon2id_v1: pdk: %w", err)
	}
	got := crypto.DeriveKey([]byte(v.Password), salt, v.KDF.OpsLimit, v.KDF.MemLimitBytes)
	if !bytes.Equal(got, want) {
		return fmt.Errorf("pdk_argon2id_v1: derived key differs from the fixture")
	}
	return nil
}

func decode32(b64 string) ([32]byte, error) {
	var out [32]byte
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("want 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}
