package e2ee

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

func withIsolatedPinStore(t *testing.T) {
	t.Helper()
	orig := config.GetConfigPath()
	config.SetConfigFile(filepath.Join(t.TempDir(), "config.json"))
	config.Load()
	setOwner(t, randKey(t, 32))
	t.Cleanup(func() {
		config.SetConfigFile(orig)
		config.Load()
	})
}

func setOwner(t *testing.T, pub []byte) {
	t.Helper()
	config.Get().PublicKey = base64.StdEncoding.EncodeToString(pub)
}

func randKey(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func markOwnSigningHistorySeeded() {
	ownSigningHistoryMu.Lock()
	defer ownSigningHistoryMu.Unlock()
	ownSigningHistorySeeded = true
	ownSigningHistoryNextTry = time.Time{}
}

func resetOwnSigningHistorySeed() {
	ownSigningHistoryMu.Lock()
	defer ownSigningHistoryMu.Unlock()
	ownSigningHistorySeeded = false
	ownSigningHistoryNextTry = time.Time{}
}

func signCiphertext(t *testing.T, priv *crypto.SigningPrivateKeySet, ct []byte) (string, string) {
	t.Helper()
	edSig, mlSig, err := crypto.SignFileBytes(bytes.NewReader(ct), priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return b64(edSig), b64(mlSig)
}

func TestSeedOwnSigningPkHistoryRetriesAfterTransientFailure(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))

	oldPub, _ := signingPair(t)
	curPub, curPriv := signingPair(t)
	blob := buildHistoryBlob(t, curPriv, oldPub.Ed25519[:], curPub.Ed25519[:])

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, `{"success":false,"message":"upstream down"}`)
			return
		}
		fmt.Fprintf(w, `{"success":true,"signing_pk_history":%q}`, b64(blob))
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "seed-test"

	savedCooldown := ownSigningHistoryRetryAfter
	ownSigningHistoryRetryAfter = 0
	resetOwnSigningHistorySeed()
	t.Cleanup(func() {
		ownSigningHistoryRetryAfter = savedCooldown
		markOwnSigningHistorySeeded()
	})

	seedOwnSigningPkHistory(curPub.Ed25519[:], curPub.Mldsa)
	if signingEdPubTrusted(oldPub.Ed25519[:]) {
		t.Fatal("a failed fetch pinned a key it never received")
	}

	seedOwnSigningPkHistory(curPub.Ed25519[:], curPub.Mldsa)
	if !signingEdPubTrusted(oldPub.Ed25519[:]) {
		t.Error("one transient failure permanently disabled history seeding")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d history fetches, want 2", got)
	}
}

func TestSeedOwnSigningPkHistoryLatchesOnEmptyHistory(t *testing.T) {
	isolateKeyEnv(t)
	setOwner(t, randKey(t, 32))
	curPub, _ := signingPair(t)

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"success":true}`)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "seed-test"

	savedCooldown := ownSigningHistoryRetryAfter
	ownSigningHistoryRetryAfter = 0
	resetOwnSigningHistorySeed()
	t.Cleanup(func() {
		ownSigningHistoryRetryAfter = savedCooldown
		markOwnSigningHistorySeeded()
	})

	seedOwnSigningPkHistory(curPub.Ed25519[:], curPub.Mldsa)
	seedOwnSigningPkHistory(curPub.Ed25519[:], curPub.Mldsa)
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d history fetches for an empty history, want 1", got)
	}
}

func TestSigningPinTOFUAndMatch(t *testing.T) {
	withIsolatedPinStore(t)

	keyA := randKey(t, crypto.Ed25519PKSize)
	keyB := randKey(t, crypto.Ed25519PKSize)

	if signingEdPubTrusted(keyA) {
		t.Fatal("key trusted before ever being seen")
	}
	if n := SigningPinCount(); n != 0 {
		t.Fatalf("fresh store count = %d, want 0", n)
	}

	rememberSigningEdPub(keyA)
	if !signingEdPubTrusted(keyA) {
		t.Fatal("first-seen key not trusted after pin")
	}
	if signingEdPubTrusted(keyB) {
		t.Fatal("unrelated key trusted")
	}
	if n := SigningPinCount(); n != 1 {
		t.Fatalf("count after one pin = %d, want 1", n)
	}

	rememberSigningEdPub(keyA)
	if n := SigningPinCount(); n != 1 {
		t.Fatalf("re-pinning same key changed count to %d, want 1", n)
	}

	rememberSigningEdPub(keyB)
	if !signingEdPubTrusted(keyA) || !signingEdPubTrusted(keyB) {
		t.Fatal("both rotated keys should stay trusted")
	}
	if n := SigningPinCount(); n != 2 {
		t.Fatalf("count after two pins = %d, want 2", n)
	}
}

func TestSigningPinPersistenceAndOwnerIsolation(t *testing.T) {
	withIsolatedPinStore(t)

	ownerA := randKey(t, 32)
	ownerB := randKey(t, 32)
	pinned := randKey(t, crypto.Ed25519PKSize)

	setOwner(t, ownerA)
	rememberSigningEdPub(pinned)
	if _, err := os.Stat(ownSigningPins.path()); err != nil {
		t.Fatalf("pin file not written: %v", err)
	}
	if !signingEdPubTrusted(pinned) {
		t.Fatal("owner A's key not trusted for owner A")
	}

	setOwner(t, ownerB)
	if signingEdPubTrusted(pinned) {
		t.Fatal("owner A's key leaked into owner B's bucket")
	}
	if n := SigningPinCount(); n != 0 {
		t.Fatalf("owner B sees %d pins, want 0", n)
	}

	setOwner(t, ownerA)
	if !signingEdPubTrusted(pinned) {
		t.Fatal("owner A's pin did not persist across owner switch")
	}
}

func TestSigningPinLegacyFlatArray(t *testing.T) {
	withIsolatedPinStore(t)

	legacyA := randKey(t, crypto.Ed25519PKSize)
	legacyB := randKey(t, crypto.Ed25519PKSize)
	raw, err := json.Marshal([]string{b64(legacyA), b64(legacyB)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ownSigningPins.path(), raw, 0600); err != nil {
		t.Fatal(err)
	}

	if !signingEdPubTrusted(legacyA) || !signingEdPubTrusted(legacyB) {
		t.Fatal("legacy flat-array keys not attributed to current account")
	}
	if n := SigningPinCount(); n != 2 {
		t.Fatalf("legacy migration count = %d, want 2", n)
	}
}

func TestSigningPinCorruptStore(t *testing.T) {
	withIsolatedPinStore(t)

	if err := os.WriteFile(ownSigningPins.path(), []byte("}{ not json at all"), 0600); err != nil {
		t.Fatal(err)
	}

	key := randKey(t, crypto.Ed25519PKSize)
	if signingEdPubTrusted(key) {
		t.Fatal("corrupt store trusted a key")
	}
	if n := SigningPinCount(); n != 0 {
		t.Fatalf("corrupt store count = %d, want 0", n)
	}

	rememberSigningEdPub(key)
	if !signingEdPubTrusted(key) {
		t.Fatal("pin over a corrupt store did not take")
	}
}

func TestSigningPinCap(t *testing.T) {
	withIsolatedPinStore(t)

	keys := make([][]byte, ownSigningPksMax+4)
	for i := range keys {
		keys[i] = randKey(t, crypto.Ed25519PKSize)
		rememberSigningEdPub(keys[i])
	}

	if n := SigningPinCount(); n != ownSigningPksMax {
		t.Fatalf("count = %d, want cap %d", n, ownSigningPksMax)
	}
	if signingEdPubTrusted(keys[0]) {
		t.Fatal("oldest key not evicted past the cap")
	}
	if !signingEdPubTrusted(keys[len(keys)-1]) {
		t.Fatal("newest key evicted")
	}
}

func ownerDownload(pub *crypto.SigningPublicKeySet, edSig, mlSig string) *api.DownloadResult {
	return &api.DownloadResult{
		SignatureEd25519: edSig,
		SignatureMldsa:   mlSig,
		SigningPkEd25519: b64(pub.Ed25519[:]),
		SigningPkMldsa:   b64(pub.Mldsa),
	}
}

func TestVerifyDownloadUnpinnedFirstContactValid(t *testing.T) {
	withIsolatedPinStore(t)

	pub, priv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct := []byte("owner ciphertext bytes")
	edSig, mlSig := signCiphertext(t, priv, ct)
	dl := ownerDownload(pub, edSig, mlSig)

	if n := SigningPinCount(); n != 0 {
		t.Fatalf("pre-verify count = %d, want 0", n)
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv); err != nil {
		t.Fatalf("valid first-contact download rejected: %v", err)
	}
	if n := SigningPinCount(); n != 1 {
		t.Fatalf("TOFU did not pin the served key: count = %d", n)
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv); err != nil {
		t.Fatalf("pinned+valid re-verify rejected: %v", err)
	}
}

func TestVerifyDownloadPinnedMismatch(t *testing.T) {
	withIsolatedPinStore(t)

	_, ownPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct := []byte("payload")
	edSig, mlSig := signCiphertext(t, otherPriv, ct)
	dl := ownerDownload(otherPub, edSig, mlSig)

	markOwnSigningHistorySeeded()

	err = VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, ownPriv)
	if err == nil || err.Error() != "owner_signing_pk_untrusted" {
		t.Fatalf("swapped signing PK not rejected, got: %v", err)
	}
}

func TestVerifyDownloadMissingSignature(t *testing.T) {
	withIsolatedPinStore(t)

	_, priv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader([]byte("x")), &api.DownloadResult{}, priv); err == nil || err.Error() != "file_signature_missing" {
		t.Fatalf("empty download result: want file_signature_missing, got %v", err)
	}
	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader([]byte("x")), nil, priv); err == nil || err.Error() != "download_result_missing" {
		t.Fatalf("nil download result: want download_result_missing, got %v", err)
	}
}

func TestVerifyDownloadCorruptStoreStillVerifies(t *testing.T) {
	withIsolatedPinStore(t)

	if err := os.WriteFile(ownSigningPins.path(), []byte("garbage-not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct := []byte("valid over a corrupt store")
	edSig, mlSig := signCiphertext(t, priv, ct)
	dl := ownerDownload(pub, edSig, mlSig)

	if err := VerifyDownloadIntegrityWithSigningKey(bytes.NewReader(ct), dl, priv); err != nil {
		t.Fatalf("corrupt store bricked a valid download: %v", err)
	}
	if n := SigningPinCount(); n != 1 {
		t.Fatalf("corrupt store not replaced by a real pin: count = %d", n)
	}
}

func TestVerifyDownloadTEEDispatchPreferred(t *testing.T) {
	withIsolatedPinStore(t)

	teePub, _, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, ownPriv, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	dl := &api.DownloadResult{
		TEESignatureEd25519: b64([]byte("tee-sig-ed")),
		TEESignatureMldsa:   b64([]byte("tee-sig-ml")),
		TEESigningPkEd25519: b64(teePub.Ed25519[:]),
		TEESigningPkMldsa:   b64(teePub.Mldsa),
	}
	err = VerifyDownloadIntegrityWithSigningKey(bytes.NewReader([]byte("sanitized")), dl, ownPriv)
	if err == nil || !strings.Contains(err.Error(), "tee") {
		t.Fatalf("TEE-signed download not routed to the TEE verifier, got: %v", err)
	}
}
