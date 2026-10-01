package e2ee

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func unlockFixture(t *testing.T) *keyFixture {
	t.Helper()
	f := newKeyFixture(t)
	f.install(t)
	SetSuppliedPassword(append([]byte(nil), f.password...))
	if _, priv := GetKeyPair(func() { t.Fatal("fixture unlock failed") }); priv == nil {
		t.Fatal("fixture unlock produced no key material")
	}
	return f
}

func TestDecodeRecipientRejectsMalformedKeySets(t *testing.T) {
	good := newKeyFixture(t)
	valid := api.ShareRecipientWithKey{
		Username:       "peer",
		PublicKey:      b64(good.pub.X25519[:]),
		PublicKeyKyber: b64(good.pub.Kyber),
	}

	cases := []struct {
		name   string
		mutate func(*api.ShareRecipientWithKey)
	}{
		{"x25519 absent", func(r *api.ShareRecipientWithKey) { r.PublicKey = "" }},
		{"kyber absent", func(r *api.ShareRecipientWithKey) { r.PublicKeyKyber = "" }},
		{"both absent", func(r *api.ShareRecipientWithKey) { r.PublicKey, r.PublicKeyKyber = "", "" }},
		{"x25519 not base64", func(r *api.ShareRecipientWithKey) { r.PublicKey = "!!!not base64!!!" }},
		{"kyber not base64", func(r *api.ShareRecipientWithKey) { r.PublicKeyKyber = "!!!not base64!!!" }},
		{"x25519 one byte short", func(r *api.ShareRecipientWithKey) { r.PublicKey = b64(make([]byte, 31)) }},
		{"x25519 one byte long", func(r *api.ShareRecipientWithKey) { r.PublicKey = b64(make([]byte, 33)) }},
		{"x25519 empty blob", func(r *api.ShareRecipientWithKey) { r.PublicKey = b64(nil) }},
		{"kyber one byte short", func(r *api.ShareRecipientWithKey) {
			r.PublicKeyKyber = b64(make([]byte, crypto.KyberPublicKeySize-1))
		}},
		{"kyber one byte long", func(r *api.ShareRecipientWithKey) {
			r.PublicKeyKyber = b64(make([]byte, crypto.KyberPublicKeySize+1))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.mutate(&r)
			got, err := decodeRecipient(r)
			if err == nil {
				t.Fatal("malformed recipient was accepted")
			}
			if got != nil {
				t.Fatal("rejected recipient still yielded a key set")
			}
		})
	}

	t.Run("well formed", func(t *testing.T) {
		got, err := decodeRecipient(valid)
		if err != nil {
			t.Fatalf("valid recipient rejected: %v", err)
		}
		if got.X25519 != good.pub.X25519 || !bytes.Equal(got.Kyber, good.pub.Kyber) {
			t.Fatal("decoded recipient does not match the encoded key set")
		}
	})
}

func TestProperty_DecodedRecipientBindsSealsToThatRecipientOnly(t *testing.T) {
	const iterations = 60
	for i := range iterations {
		alice := newKeyFixture(t)
		bob := newKeyFixture(t)

		recipient, err := decodeRecipient(api.ShareRecipientWithKey{
			Username:       "alice",
			PublicKey:      b64(alice.pub.X25519[:]),
			PublicKeyKyber: b64(alice.pub.Kyber),
		})
		if err != nil {
			t.Fatalf("iteration %d: decode: %v", i, err)
		}

		name := "report-" + hex.EncodeToString(randKey(t, 8)) + ".pdf"
		sealed, err := crypto.SealDisplayName(name, recipient)
		if err != nil {
			t.Fatalf("iteration %d: seal: %v", i, err)
		}

		opened, err := crypto.UnsealDisplayName(sealed, alice.priv)
		if err != nil {
			t.Fatalf("iteration %d: intended recipient cannot open its own seal: %v", i, err)
		}
		if opened != name {
			t.Fatalf("iteration %d: round trip returned %q, want %q", i, opened, name)
		}
		if _, err := crypto.UnsealDisplayName(sealed, bob.priv); err == nil {
			t.Fatalf("iteration %d: a seal for alice opened with bob's private key", i)
		}
	}
}

func TestDecodedRecipientWithMixedKeyHalvesOpensForNobody(t *testing.T) {
	alice := newKeyFixture(t)
	mallory := newKeyFixture(t)

	mixed, err := decodeRecipient(api.ShareRecipientWithKey{
		Username:       "alice",
		PublicKey:      b64(alice.pub.X25519[:]),
		PublicKeyKyber: b64(mallory.pub.Kyber),
	})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	sealed, err := crypto.SealDisplayName("quarterly.xlsx", mixed)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := crypto.UnsealDisplayName(sealed, mallory.priv); err == nil {
		t.Fatal("swapping the kyber half handed the seal to the swapper")
	}
	if _, err := crypto.UnsealDisplayName(sealed, alice.priv); err == nil {
		t.Fatal("a mixed key set opened with the x25519 half alone; the hybrid binding is not strict")
	}
}

func TestGetPublicKeyFailsClosedOnMalformedConfig(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.Config)
	}{
		{"unconfigured", func(c *config.Config) { c.PublicKey, c.PublicKeyKyber = "", "" }},
		{"x25519 one byte short", func(c *config.Config) { c.PublicKey = b64(make([]byte, 31)) }},
		{"kyber one byte short", func(c *config.Config) {
			c.PublicKeyKyber = b64(make([]byte, crypto.KyberPublicKeySize-1))
		}},
		{"kyber not base64", func(c *config.Config) { c.PublicKeyKyber = "!!!not base64!!!" }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			f := newKeyFixture(t)
			f.install(t)
			tc.mutate(config.Get())

			exits := 0
			pub := GetPublicKey(func() { exits++ })
			if pub != nil {
				t.Fatal("malformed config produced a public key set")
			}
			if exits == 0 {
				t.Fatal("GetPublicKey never signalled failure to the caller")
			}
			if cachedPub != nil {
				t.Fatal("a rejected public key reached the cache")
			}
		})
	}
}

func TestDecryptE2EENameFailsClosedInsteadOfLeakingPartialText(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)
	other := newKeyFixture(t)

	const plaintextName = "Q3 forecast.numbers"
	sealed, err := crypto.SealDisplayName(plaintextName, f.pub)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if got := DecryptE2EEName(b64(sealed)); got != plaintextName {
		t.Fatalf("own sealed name decrypted to %q, want %q", got, plaintextName)
	}

	foreign, err := crypto.SealDisplayName(plaintextName, other.pub)
	if err != nil {
		t.Fatalf("seal for other account: %v", err)
	}
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01

	cases := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"not base64", "!!!not base64!!!"},
		{"truncated blob", b64(sealed[:len(sealed)-1])},
		{"header only", b64(sealed[:32])},
		{"tampered tag", b64(tampered)},
		{"sealed to another account", b64(foreign)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecryptE2EEName(tc.input)
			if got != "(encrypted)" {
				t.Fatalf("undecryptable name rendered as %q; only the sealed placeholder is safe", got)
			}
		})
	}

	t.Run("locked account", func(t *testing.T) {
		isolateKeyEnv(t)
		if got := DecryptE2EEName(b64(sealed)); got != "(encrypted)" {
			t.Fatalf("name rendered as %q with no keys configured", got)
		}
	})
}

func TestComputePathTokenMapsWithoutKeysEmitsNothing(t *testing.T) {
	isolateKeyEnv(t)

	canonical, legacy := ComputePathTokenMaps([]string{"docs/report.txt"}, func() {
		t.Error("ComputePathTokenMaps signalled failure for an account without keys")
	})
	if canonical != "" || legacy != "" {
		t.Fatalf("keyless account produced tokens: canonical=%q legacy=%q", canonical, legacy)
	}

	options := map[string]string{}
	AddPathTokens(options, []string{"docs/report.txt"}, func() {})
	if len(options) != 0 {
		t.Fatalf("keyless account populated options: %v", options)
	}
}

func TestComputePathTokenMapsKeysByNormalizedPath(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)

	canonical, legacy := ComputePathTokenMaps([]string{`docs\sub\report.txt`}, func() {
		t.Fatal("token build signalled failure")
	})
	if legacy != "" {
		t.Errorf("an unaffected path emitted a legacy map: %s", legacy)
	}

	var tokens map[string]string
	if err := json.Unmarshal([]byte(canonical), &tokens); err != nil {
		t.Fatalf("canonical map is not JSON: %v (%s)", err, canonical)
	}
	got, ok := tokens["docs/sub/report.txt"]
	if !ok {
		t.Fatalf("token map is not keyed by the slash-normalized path: %v", tokens)
	}
	if _, unwanted := tokens[`docs\sub\report.txt`]; unwanted {
		t.Error("token map leaked a backslash key")
	}

	want, err := crypto.ComputePathToken(f.nameKey, "docs/sub/report.txt")
	if err != nil {
		t.Fatalf("reference token: %v", err)
	}
	if got != hex.EncodeToString(want) {
		t.Fatal("token was not computed under this account's name key")
	}
}

func TestAddPathTokensOffersLegacyTokenOnlyForAffectedPaths(t *testing.T) {
	isolateKeyEnv(t)
	unlockFixture(t)

	const affected = "İstanbul/notes.txt"
	if !crypto.PathTokenNeedsLegacy(affected) {
		t.Fatalf("%q no longer diverges; pick another path for the legacy case", affected)
	}

	plain := map[string]string{}
	AddPathTokens(plain, []string{"docs/report.txt"}, func() { t.Fatal("token build signalled failure") })
	if _, ok := plain["path_tokens"]; !ok {
		t.Fatal("path_tokens was not set for a normal path")
	}
	if _, ok := plain["path_tokens_legacy"]; ok {
		t.Error("path_tokens_legacy was set for a path both normalizers agree on")
	}

	mixed := map[string]string{}
	AddPathTokens(mixed, []string{"docs/report.txt", affected}, func() {
		t.Fatal("token build signalled failure")
	})
	legacyJSON, ok := mixed["path_tokens_legacy"]
	if !ok {
		t.Fatal("path_tokens_legacy missing for a path the normalizers disagree on; pre-convergence files would 404")
	}
	var legacyMap, canonicalMap map[string]string
	if err := json.Unmarshal([]byte(legacyJSON), &legacyMap); err != nil {
		t.Fatalf("legacy map is not JSON: %v", err)
	}
	if err := json.Unmarshal([]byte(mixed["path_tokens"]), &canonicalMap); err != nil {
		t.Fatalf("canonical map is not JSON: %v", err)
	}
	if len(legacyMap) != 1 {
		t.Fatalf("legacy map carries %d entries, want only the affected path: %v", len(legacyMap), legacyMap)
	}
	for path, legacyToken := range legacyMap {
		if canonicalMap[path] == legacyToken {
			t.Errorf("legacy token for %q equals the canonical one; the fallback adds nothing", path)
		}
	}
	if _, leaked := legacyMap["docs/report.txt"]; leaked {
		t.Error("an unaffected path was given a legacy token")
	}
}

func TestResolveAndBaseNameStripsLeadingSlash(t *testing.T) {
	cases := []struct {
		in       string
		wantFull string
		wantBase string
	}{
		{"/docs/report.txt", "docs/report.txt", "report.txt"},
		{"/report.txt", "report.txt", "report.txt"},
		{"docs/report.txt", "docs/report.txt", "report.txt"},
		{"/a/b/c", "a/b/c", "c"},
	}
	for _, tc := range cases {
		full, base := ResolveAndBaseName(tc.in)
		if full != tc.wantFull {
			t.Errorf("ResolveAndBaseName(%q) full = %q, want %q", tc.in, full, tc.wantFull)
		}
		if base != tc.wantBase {
			t.Errorf("ResolveAndBaseName(%q) base = %q, want %q", tc.in, base, tc.wantBase)
		}
		if strings.HasPrefix(full, "/") {
			t.Errorf("ResolveAndBaseName(%q) kept a leading slash", tc.in)
		}
	}
}

type teeServer struct {
	mu    sync.Mutex
	build func(*api.TeeAttestationResponse)
}

func newTeeServer(t *testing.T) *teeServer {
	t.Helper()
	s := &teeServer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		build := s.build
		s.mu.Unlock()
		var resp api.TeeAttestationResponse
		if build != nil {
			build(&resp)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&resp)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	return s
}

func (s *teeServer) set(build func(*api.TeeAttestationResponse)) {
	s.mu.Lock()
	s.build = build
	s.mu.Unlock()
}

func trustedSgx(pub *crypto.PublicKeySet) func(*api.TeeAttestationResponse) {
	return func(r *api.TeeAttestationResponse) {
		r.Success = true
		r.Enabled = true
		r.Available = true
		r.Attestation.EnclavePublicKey = b64(pub.X25519[:])
		r.Attestation.EnclavePublicKeyKyber = b64(pub.Kyber)
		r.Attestation.AttestationMode = "epid"
		r.Attestation.Mrenclave = "aa" + strings.Repeat("bb", 31)
		r.Attestation.SgxQuote = b64([]byte("quote"))
		r.Attestation.VerificationStatus = "trusted"
	}
}

func TestFetchTeeEnclaveKeySetAttestationGate(t *testing.T) {
	enclavePub, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}

	cases := []struct {
		name       string
		mutate     func(*api.TeeAttestationResponse)
		wantKeySet bool
	}{
		{"sgx trusted", nil, true},
		{"sgx unverified", func(r *api.TeeAttestationResponse) {
			r.Attestation.VerificationStatus = "unverified"
		}, false},
		{"sgx untrusted", func(r *api.TeeAttestationResponse) {
			r.Attestation.VerificationStatus = "untrusted"
		}, false},
		{"untrusted outside sgx", func(r *api.TeeAttestationResponse) {
			r.Attestation.AttestationMode = "dev"
			r.Attestation.Mrenclave = ""
			r.Attestation.SgxQuote = ""
			r.Attestation.VerificationStatus = "untrusted"
		}, false},
		{"dev mode unverified stays permissive", func(r *api.TeeAttestationResponse) {
			r.Attestation.AttestationMode = "dev"
			r.Attestation.Mrenclave = ""
			r.Attestation.SgxQuote = ""
			r.Attestation.VerificationStatus = "unverified"
		}, true},
		{"scanner unavailable", func(r *api.TeeAttestationResponse) { r.Available = false }, false},
		{"request unsuccessful", func(r *api.TeeAttestationResponse) { r.Success = false }, false},
		{"x25519 one byte short", func(r *api.TeeAttestationResponse) {
			r.Attestation.EnclavePublicKey = b64(make([]byte, 31))
		}, false},
		{"x25519 not base64", func(r *api.TeeAttestationResponse) {
			r.Attestation.EnclavePublicKey = "!!!not base64!!!"
		}, false},
		{"kyber one byte short", func(r *api.TeeAttestationResponse) {
			r.Attestation.EnclavePublicKeyKyber = b64(make([]byte, crypto.KyberPublicKeySize-1))
		}, false},
		{"kyber absent", func(r *api.TeeAttestationResponse) {
			r.Attestation.EnclavePublicKeyKyber = ""
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			srv := newTeeServer(t)
			srv.set(func(r *api.TeeAttestationResponse) {
				trustedSgx(enclavePub)(r)
				if tc.mutate != nil {
					tc.mutate(r)
				}
			})

			got := FetchTeeEnclaveKeySet()
			if tc.wantKeySet {
				if got == nil {
					t.Fatal("a key set the CLI should accept was refused")
				}
				if got.X25519 != enclavePub.X25519 || !bytes.Equal(got.Kyber, enclavePub.Kyber) {
					t.Fatal("accepted key set does not match what the server served")
				}
				return
			}
			if got != nil {
				t.Fatal("an untrusted or malformed attestation yielded a sealing target")
			}
			if cachedTeeEnclaveKeySet != nil {
				t.Fatal("a refused attestation was cached")
			}
		})
	}
}

func TestFetchTeeEnclaveKeySetDoesNotCacheFailures(t *testing.T) {
	isolateKeyEnv(t)
	enclavePub, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}
	srv := newTeeServer(t)

	srv.set(func(r *api.TeeAttestationResponse) {
		trustedSgx(enclavePub)(r)
		r.Attestation.VerificationStatus = "unverified"
	})
	if got := FetchTeeEnclaveKeySet(); got != nil {
		t.Fatal("an unverified SGX attestation was accepted")
	}

	srv.set(trustedSgx(enclavePub))
	got := FetchTeeEnclaveKeySet()
	if got == nil {
		t.Fatal("a transient attestation failure was cached and bricked later uploads")
	}
	if got.X25519 != enclavePub.X25519 {
		t.Fatal("recovered key set does not match the served one")
	}
}

func TestFetchTeeEnclaveKeySetCachesSuccess(t *testing.T) {
	isolateKeyEnv(t)
	enclavePub, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}
	srv := newTeeServer(t)
	srv.set(trustedSgx(enclavePub))

	first := FetchTeeEnclaveKeySet()
	if first == nil {
		t.Fatal("a trusted attestation was refused")
	}

	srv.set(func(r *api.TeeAttestationResponse) { r.Success = false })
	second := FetchTeeEnclaveKeySet()
	if second == nil {
		t.Fatal("a cached key set was dropped after one bad response")
	}
	if second.X25519 != enclavePub.X25519 {
		t.Fatal("cached key set changed identity")
	}
}

func TestHandleE2EEUploadProducesRecoverableCiphertext(t *testing.T) {
	isolateKeyEnv(t)
	tmpDir := t.TempDir()
	workDir := t.TempDir()
	t.Setenv("TMPDIR", tmpDir)
	t.Setenv("TEMP", tmpDir)
	t.Setenv("TMP", tmpDir)

	f := unlockFixture(t)
	enclavePub, enclavePriv, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}
	srv := newTeeServer(t)
	srv.set(trustedSgx(enclavePub))

	plaintext := randKey(t, 3*1024+7)
	localPath := filepath.Join(workDir, "payload.bin")
	if err := os.WriteFile(localPath, plaintext, 0600); err != nil {
		t.Fatalf("write source: %v", err)
	}

	encPath, sealedB64, metaB64, teeSealedB64, hmacHex := HandleE2EEUpload(localPath, func() {
		t.Fatal("upload path signalled failure")
	})
	if encPath == "" {
		t.Fatal("upload produced no ciphertext path")
	}
	t.Cleanup(func() { os.Remove(encPath) })

	sealed, err := decodeB64Required(sealedB64, "sealed_key")
	if err != nil {
		t.Fatalf("sealed key: %v", err)
	}
	dataKey, err := crypto.UnsealDataKey(sealed, f.priv)
	if err != nil {
		t.Fatalf("owner cannot unseal the data key it uploaded: %v", err)
	}
	if len(dataKey) != crypto.KeySize {
		t.Fatalf("data key is %d bytes, want %d", len(dataKey), crypto.KeySize)
	}

	teeSealed, err := decodeB64Required(teeSealedB64, "tee_sealed_key")
	if err != nil {
		t.Fatalf("tee sealed key: %v", err)
	}
	teeDataKey, err := crypto.UnsealDataKey(teeSealed, enclavePriv)
	if err != nil {
		t.Fatalf("enclave cannot unseal its handoff key: %v", err)
	}
	if !bytes.Equal(dataKey, teeDataKey) {
		t.Fatal("the enclave was handed a different key than the owner; the scan would run on garbage")
	}

	metaJSON, err := decodeB64Required(metaB64, "enc_meta")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	var meta crypto.EncryptionMetadata
	if err := json.Unmarshal(metaJSON, &meta); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}

	outPath := filepath.Join(workDir, "roundtrip.bin")
	if err := crypto.DecryptFile(encPath, outPath, dataKey, &meta); err != nil {
		t.Fatalf("uploaded ciphertext does not decrypt with its own sealed key: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read round trip: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip through the upload path changed the file contents")
	}

	plaintextDigest := sha256.Sum256(plaintext)
	wantHmac, err := crypto.ComputePlaintextHmac(hex.EncodeToString(plaintextDigest[:]), f.nameKey)
	if err != nil {
		t.Fatalf("reference hmac: %v", err)
	}
	if hmacHex != wantHmac {
		t.Fatal("plaintext hmac was not computed under this account's name key")
	}

	stranger := newKeyFixture(t)
	if _, err := crypto.UnsealDataKey(sealed, stranger.priv); err == nil {
		t.Fatal("the uploaded data key opened with an unrelated private key")
	}
}

func TestHandleE2EEUploadRefusesAndCleansUpWhenEnclaveUntrusted(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*api.TeeAttestationResponse)
	}{
		{"scanner unavailable", func(r *api.TeeAttestationResponse) { r.Available = false }},
		{"sgx attestation unverified", func(r *api.TeeAttestationResponse) {
			r.Attestation.VerificationStatus = "unverified"
		}},
		{"enclave key malformed", func(r *api.TeeAttestationResponse) {
			r.Attestation.EnclavePublicKeyKyber = b64(make([]byte, 8))
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			tmpDir := t.TempDir()
			workDir := t.TempDir()
			t.Setenv("TMPDIR", tmpDir)
			t.Setenv("TEMP", tmpDir)
			t.Setenv("TMP", tmpDir)

			unlockFixture(t)
			enclavePub, _, err := crypto.GenerateHybridKeyPair()
			if err != nil {
				t.Fatalf("enclave keygen: %v", err)
			}
			srv := newTeeServer(t)
			srv.set(func(r *api.TeeAttestationResponse) {
				trustedSgx(enclavePub)(r)
				tc.mutate(r)
			})

			localPath := filepath.Join(workDir, "payload.bin")
			if err := os.WriteFile(localPath, randKey(t, 2048), 0600); err != nil {
				t.Fatalf("write source: %v", err)
			}

			exits := 0
			encPath, sealedB64, metaB64, teeSealedB64, hmacHex := HandleE2EEUpload(localPath, func() { exits++ })

			if exits == 0 {
				t.Fatal("upload never signalled failure to the caller")
			}
			for _, field := range []struct{ name, value string }{
				{"encryptedPath", encPath},
				{"sealedKey", sealedB64},
				{"encMeta", metaB64},
				{"teeSealedKey", teeSealedB64},
				{"plaintextHmac", hmacHex},
			} {
				if field.value != "" {
					t.Errorf("refused upload still returned %s = %q", field.name, field.value)
				}
			}

			leftovers, err := filepath.Glob(filepath.Join(tmpDir, "pigcloud-e2ee-*"))
			if err != nil {
				t.Fatalf("glob: %v", err)
			}
			if len(leftovers) != 0 {
				t.Errorf("refused upload left ciphertext behind: %v", leftovers)
			}
		})
	}
}

func TestSignEncryptedFileProducesVerifiableSignatures(t *testing.T) {
	isolateKeyEnv(t)
	f := unlockFixture(t)

	ciphertext := randKey(t, 8192)
	path := filepath.Join(t.TempDir(), "ciphertext.bin")
	if err := os.WriteFile(path, ciphertext, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	sigEd, sigMl, pkEd, pkMl := SignEncryptedFile(path, func() { t.Fatal("signing signalled failure") })
	for _, field := range []struct{ name, value string }{
		{"signature_ed25519", sigEd},
		{"signature_mldsa", sigMl},
		{"signing_pk_ed25519", pkEd},
		{"signing_pk_mldsa", pkMl},
	} {
		if field.value == "" {
			t.Fatalf("%s was not produced", field.name)
		}
	}
	if pkEd != b64(f.signPub.Ed25519[:]) || pkMl != b64(f.signPub.Mldsa) {
		t.Fatal("uploaded signing public keys are not this account's")
	}

	dl := &api.DownloadResult{
		SignatureEd25519: sigEd,
		SignatureMldsa:   sigMl,
		SigningPkEd25519: pkEd,
		SigningPkMldsa:   pkMl,
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ciphertext), dl, f.signPriv); err != nil {
		t.Fatalf("the CLI's own signatures fail the CLI's own verifier: %v", err)
	}

	t.Run("rejects a flipped byte", func(t *testing.T) {
		tampered := append([]byte(nil), ciphertext...)
		tampered[len(tampered)/2] ^= 0x01
		if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(tampered), dl, f.signPriv); err == nil {
			t.Fatal("a modified byte verified against the original signature")
		}
	})

	t.Run("rejects truncation", func(t *testing.T) {
		if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ciphertext[:len(ciphertext)-1]), dl, f.signPriv); err == nil {
			t.Fatal("truncated ciphertext verified against the full-file signature")
		}
	})

	t.Run("rejects a dropped mldsa signature", func(t *testing.T) {
		halfSigned := *dl
		halfSigned.SignatureMldsa = ""
		if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ciphertext), &halfSigned, f.signPriv); err == nil {
			t.Fatal("ed25519 alone satisfied the strict-AND verifier")
		}
	})
}

func TestSignEncryptedFileWithoutSigningKeysReturnsNothing(t *testing.T) {
	isolateKeyEnv(t)
	f := newKeyFixture(t)
	f.installEncryptionOnly(t)
	SetSuppliedPassword(append([]byte(nil), f.password...))
	if _, priv := GetKeyPair(func() { t.Fatal("unlock failed") }); priv == nil {
		t.Fatal("unlock produced no key material")
	}

	path := filepath.Join(t.TempDir(), "ciphertext.bin")
	if err := os.WriteFile(path, randKey(t, 1024), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	exits := 0
	sigEd, sigMl, pkEd, pkMl := SignEncryptedFile(path, func() { exits++ })

	if exits == 0 {
		t.Fatal("signing without keys never signalled failure to the caller")
	}
	for _, field := range []struct{ name, value string }{
		{"signature_ed25519", sigEd},
		{"signature_mldsa", sigMl},
		{"signing_pk_ed25519", pkEd},
		{"signing_pk_mldsa", pkMl},
	} {
		if field.value != "" {
			t.Errorf("keyless signing returned %s = %q; a partial signature set would upload unverifiable", field.name, field.value)
		}
	}
}

func TestTeeScannerDisabledByServerOnlyOnAnExplicitAnswer(t *testing.T) {
	enclavePub, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("enclave keygen: %v", err)
	}

	cases := []struct {
		name         string
		mutate       func(*api.TeeAttestationResponse)
		wantDisabled bool
	}{
		{"scanner switched off", func(r *api.TeeAttestationResponse) {
			r.Enabled = false
			r.Available = false
		}, true},
		{"enabled and serving", nil, false},
		{"enabled but unreachable", func(r *api.TeeAttestationResponse) {
			r.Available = false
		}, false},
		{"probe itself failed", func(r *api.TeeAttestationResponse) {
			r.Success = false
			r.Enabled = false
		}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			isolateKeyEnv(t)
			teeScannerDisabledByServer = false
			srv := newTeeServer(t)
			srv.set(func(r *api.TeeAttestationResponse) {
				trustedSgx(enclavePub)(r)
				r.Enabled = true
				if tc.mutate != nil {
					tc.mutate(r)
				}
			})

			FetchTeeEnclaveKeySet()
			if got := TeeScannerDisabledByServer(); got != tc.wantDisabled {
				t.Fatalf("disabled verdict = %v, want %v", got, tc.wantDisabled)
			}
		})
	}
}
