package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

type signingAnswer struct {
	ed, ml           string
	mode, mrenclave  string
	quote, status    string
	sealX, sealKyber string
}

func serveSigningKeys(t *testing.T, answer *atomic.Pointer[signingAnswer]) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a := answer.Load()
		body := map[string]any{
			"success": true, "enabled": true, "available": true,
			"attestation": map[string]any{
				"attestation_mode":           a.mode,
				"mrenclave":                  a.mrenclave,
				"sgx_quote":                  a.quote,
				"verification_status":        a.status,
				"enclave_signing_pk_ed25519": a.ed,
				"enclave_signing_pk_mldsa":   a.ml,
				"enclave_public_key":         a.sealX,
				"enclave_public_key_kyber":   a.sealKyber,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "signing-pin-test"
}

func rebuiltEnclave(t *testing.T) signingAnswer {
	t.Helper()
	ed, ml := servedPair(t)
	return signingAnswer{
		ed: ed, ml: ml, mode: "none", status: "unverified",
		sealX:     b64(randKey(t, 32)),
		sealKyber: b64(randKey(t, crypto.KyberPublicKeySize)),
	}
}

func forgetAttestedSigningPk(t *testing.T) {
	t.Helper()
	teeSigningAttMu.Lock()
	teeSigningAtt = nil
	teeSigningAttNextTry = time.Time{}
	teeSigningAttMu.Unlock()
	t.Cleanup(func() {
		teeSigningAttMu.Lock()
		teeSigningAtt = nil
		teeSigningAttNextTry = time.Time{}
		teeSigningAttMu.Unlock()
	})
}

func servedPair(t *testing.T) (string, string) {
	t.Helper()
	return b64(randKey(t, crypto.Ed25519PKSize)), b64(randKey(t, crypto.Mldsa44PKSize))
}

func accept(t *testing.T, ed, ml string) error {
	t.Helper()
	commit, err := checkTeeSigningPks(ed, ml)
	if err != nil {
		return err
	}
	commit()
	return nil
}

func offerFor(t *testing.T, edB64, mlB64 string) *TeeAttestationOffer {
	t.Helper()
	return &TeeAttestationOffer{
		Ed25519: edB64, Mldsa: mlB64,
		posture: teeAttestationPosture{Mode: "none", SealingPk: b64(randKey(t, 32))},
	}
}

func TestTeeSigningPinFirstContactPinsTheAttestedKey(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	ed, ml := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: ed, ml: ml, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)

	if err := accept(t, ed, ml); err != nil {
		t.Fatalf("first contact with the attested key was refused: %v", err)
	}
	pinned, retired := TeeSigningPins()
	if pinned == nil || pinned.Ed25519 != ed || pinned.Mldsa != ml {
		t.Fatalf("pinned = %+v, want the served pair", pinned)
	}
	if len(retired) != 0 {
		t.Fatalf("retired = %+v on first contact, want none", retired)
	}
}

func TestTeeSigningPinRefusesTheRekeyedKeyUntilRepin(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	oldEd, oldMl := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: oldEd, ml: oldMl, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}

	newEd, newMl := servedPair(t)
	err := accept(t, newEd, newMl)
	if err == nil {
		t.Fatal("a file signed by an unpinned key was accepted without a repin")
	}
	if !strings.Contains(err.Error(), "tee_signing_pk_changed") {
		t.Fatalf("refusal = %v, want tee_signing_pk_changed", err)
	}
	if !strings.Contains(err.Error(), "pc te repin") {
		t.Fatalf("refusal = %v, want it to name the repin verb", err)
	}
}

func TestTeeSigningRepinRetiresTheOldKeyAndKeepsItReadable(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	oldEd, oldMl := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: oldEd, ml: oldMl, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}

	rebuilt := rebuiltEnclave(t)
	newEd, newMl := rebuilt.ed, rebuilt.ml
	answer.Store(&rebuilt)
	offer, err := OfferedTeeSigningPk()
	if err != nil {
		t.Fatalf("the rekeyed server offered nothing: %v", err)
	}
	if offer.Ed25519 != newEd || offer.Mldsa != newMl {
		t.Fatalf("offer = %+v, want the rekeyed pair", offer)
	}
	if err := RepinTeeSigningPk(offer); err != nil {
		t.Fatalf("repin refused: %v", err)
	}

	if err := accept(t, newEd, newMl); err != nil {
		t.Fatalf("after the repin the new key was still refused: %v", err)
	}
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("a file signed by the retired key was refused after the repin: %v", err)
	}

	pinned, retired := TeeSigningPins()
	if pinned == nil || pinned.Ed25519 != newEd {
		t.Fatalf("pinned = %+v, want the rekeyed pair", pinned)
	}
	if len(retired) != 1 || retired[0].Ed25519 != oldEd || retired[0].Mldsa != oldMl {
		t.Fatalf("retired = %+v, want exactly the superseded pair", retired)
	}
	if retired[0].RetiredAt == "" {
		t.Fatal("the retired entry carries no retirement date")
	}
}

func TestTeeSigningRetiredKeyDoesNotDemoteThePin(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	oldEd, oldMl := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: oldEd, ml: oldMl, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}
	newEd, newMl := servedPair(t)
	if err := RepinTeeSigningPk(offerFor(t, newEd, newMl)); err != nil {
		t.Fatalf("repin refused: %v", err)
	}

	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("retired key refused: %v", err)
	}
	pinned, _ := TeeSigningPins()
	if pinned == nil || pinned.Ed25519 != newEd || pinned.Mldsa != newMl {
		t.Fatalf("pinned = %+v after a retired-key download, want the repinned pair", pinned)
	}
}

func TestTeeSigningPinRefusesAKeyThatWasNeverAccepted(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	oldEd, oldMl := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: oldEd, ml: oldMl, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}
	newEd, newMl := servedPair(t)
	if err := RepinTeeSigningPk(offerFor(t, newEd, newMl)); err != nil {
		t.Fatalf("repin refused: %v", err)
	}

	strangerEd, strangerMl := servedPair(t)
	err := accept(t, strangerEd, strangerMl)
	if err == nil {
		t.Fatal("a key that was never pinned or retired was accepted")
	}
	if !strings.Contains(err.Error(), "tee_signing_pk_changed") {
		t.Fatalf("refusal = %v, want tee_signing_pk_changed", err)
	}
}

func TestTeeSigningForgetRetiredKeyRefusesItsFilesAgain(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	oldEd, oldMl := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: oldEd, ml: oldMl, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}
	newEd, newMl := servedPair(t)
	if err := RepinTeeSigningPk(offerFor(t, newEd, newMl)); err != nil {
		t.Fatalf("repin refused: %v", err)
	}

	fp := TeeSigningKeyFingerprint(oldEd, oldMl)
	if !ForgetRetiredTeeSigningPk(fp) {
		t.Fatalf("forgetting the retired key by fingerprint %q found nothing", fp)
	}
	if ForgetRetiredTeeSigningPk(fp) {
		t.Fatal("forgetting the same fingerprint twice reported a second removal")
	}
	if err := accept(t, oldEd, oldMl); err == nil {
		t.Fatal("a forgotten key still verifies")
	}
}

func TestTeeSigningSidecarDeletionReAnchorsOnTheCurrentKey(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	oldEd, oldMl := servedPair(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&signingAnswer{ed: oldEd, ml: oldMl, mode: "none", status: "unverified"})
	serveSigningKeys(t, &answer)
	if err := accept(t, oldEd, oldMl); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}

	if err := os.Remove(teeSigningPksPath()); err != nil {
		t.Fatalf("removing the sidecar: %v", err)
	}
	newEd, newMl := servedPair(t)
	answer.Store(&signingAnswer{ed: newEd, ml: newMl, mode: "none", status: "unverified"})
	teeSigningAttMu.Lock()
	teeSigningAtt = nil
	teeSigningAttNextTry = time.Time{}
	teeSigningAttMu.Unlock()

	if err := accept(t, newEd, newMl); err != nil {
		t.Fatalf("after deleting the sidecar the current key was refused: %v", err)
	}
	if err := accept(t, oldEd, oldMl); err == nil {
		t.Fatal("deleting the sidecar kept the old key readable; it must not")
	}
	_, retired := TeeSigningPins()
	if len(retired) != 0 {
		t.Fatalf("retired = %+v after a sidecar delete, want none", retired)
	}
}

func TestTeeSigningRetiredListStaysCapped(t *testing.T) {
	withIsolatedPinStore(t)
	ed, ml := servedPair(t)
	recordTeeSigningPk(ed, ml)
	for i := range teeRetiredPkLimit + 4 {
		nextEd, nextMl := servedPair(t)
		if err := RepinTeeSigningPk(offerFor(t, nextEd, nextMl)); err != nil {
			t.Fatalf("repin %d refused: %v", i, err)
		}
	}
	_, retired := TeeSigningPins()
	if len(retired) != teeRetiredPkLimit {
		t.Fatalf("retired list holds %d entries, want the %d cap", len(retired), teeRetiredPkLimit)
	}
}

func TestTeeSigningRepinRejectsTheAttestationAlreadyPinned(t *testing.T) {
	withIsolatedPinStore(t)
	ed, ml := servedPair(t)
	recordTeeSigningPk(ed, ml)
	offer := offerFor(t, ed, ml)
	if err := RepinTeeSigningPk(offer); err != nil {
		t.Fatalf("the same key with an unrecorded posture is still a change: %v", err)
	}
	if err := RepinTeeSigningPk(offer); err == nil {
		t.Fatal("repinning the attestation already pinned reported a change")
	}
	_, retired := TeeSigningPins()
	if len(retired) != 0 {
		t.Fatalf("a no-op repin retired %+v", retired)
	}
}

func TestTeeSigningRepinRefusesAGarbageKey(t *testing.T) {
	withIsolatedPinStore(t)
	ed, ml := servedPair(t)
	recordTeeSigningPk(ed, ml)
	cases := map[string]*TeeAttestationOffer{
		"not base64":     {Ed25519: "!!!!", Mldsa: ml},
		"short ed25519":  {Ed25519: b64(randKey(t, 16)), Mldsa: ml},
		"short mldsa":    {Ed25519: ed, Mldsa: b64(randKey(t, 64))},
		"empty ed25519":  {Ed25519: "", Mldsa: ml},
		"empty key pair": {},
	}
	for name, offer := range cases {
		t.Run(name, func(t *testing.T) {
			err := RepinTeeSigningPk(offer)
			if err == nil {
				t.Fatal("a key set that is not a valid enclave key pair was pinned")
			}
			if !strings.Contains(err.Error(), "tee_signing_pk_wrong_size") {
				t.Fatalf("refusal = %v, want tee_signing_pk_wrong_size", err)
			}
			pinned, retired := TeeSigningPins()
			if pinned == nil || pinned.Ed25519 != ed || pinned.Mldsa != ml {
				t.Fatalf("pinned = %+v, want the untouched original", pinned)
			}
			if len(retired) != 0 {
				t.Fatalf("a refused repin retired %+v", retired)
			}
		})
	}
}

func TestTeeSigningOfferRefusesAGarbageServedKey(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	bad := rebuiltEnclave(t)
	bad.ml = b64(randKey(t, 64))
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&bad)
	serveSigningKeys(t, &answer)

	offer, err := OfferedTeeSigningPk()
	if err == nil {
		t.Fatalf("a wrong-sized served signing key was offered for pinning: %+v", offer)
	}
	if !strings.Contains(err.Error(), "tee_signing_pk_wrong_size") {
		t.Fatalf("refusal = %v, want tee_signing_pk_wrong_size", err)
	}
}

func TestTeeSigningRepinAlsoMovesTheSealingPosture(t *testing.T) {
	withIsolatedPinStore(t)
	forgetAttestedSigningPk(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
	first := rebuiltEnclave(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&first)
	serveSigningKeys(t, &answer)

	if err := accept(t, first.ed, first.ml); err != nil {
		t.Fatalf("first contact refused: %v", err)
	}
	if fetchFresh() == nil {
		t.Fatalf("the first upload was refused: %v", TeeEnclaveKeyRefusal())
	}

	rebuilt := rebuiltEnclave(t)
	answer.Store(&rebuilt)
	offer, err := OfferedTeeSigningPk()
	if err != nil {
		t.Fatalf("the rebuilt server offered nothing: %v", err)
	}
	if err := RepinTeeSigningPk(offer); err != nil {
		t.Fatalf("repin refused: %v", err)
	}

	if fetchFresh() == nil {
		t.Fatalf("after the repin the upload path still refuses: %v", TeeEnclaveKeyRefusal())
	}
	if err := accept(t, rebuilt.ed, rebuilt.ml); err != nil {
		t.Fatalf("after the repin the new signing key was refused: %v", err)
	}
	if err := accept(t, first.ed, first.ml); err != nil {
		t.Fatalf("the retired signing key was refused after the repin: %v", err)
	}
}

func TestTeeAttestationPostureErrorNamesTheRepinVerb(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
	first := rebuiltEnclave(t)
	var answer atomic.Pointer[signingAnswer]
	answer.Store(&first)
	serveSigningKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("first contact refused: %v", TeeEnclaveKeyRefusal())
	}

	rebuilt := rebuiltEnclave(t)
	answer.Store(&rebuilt)
	if fetchFresh() != nil {
		t.Fatal("a moved sealing key was accepted without a repin")
	}
	err := TeeEnclaveKeyRefusal()
	if err == nil || !strings.Contains(err.Error(), "tee_enclave_pk_changed") {
		t.Fatalf("refusal = %v, want tee_enclave_pk_changed", err)
	}
	if !strings.Contains(err.Error(), "pc te repin") {
		t.Fatalf("refusal = %v, want it to name the repin verb before the sidecar", err)
	}
	if !strings.Contains(err.Error(), "drops every retired signing key") {
		t.Fatalf("refusal = %v, want it to say what deleting the sidecar costs", err)
	}
}

func TestTeeSigningFingerprintMatchesTheWebConstruction(t *testing.T) {
	ed := b64([]byte("ed-key-bytes"))
	ml := b64([]byte("ml-key-bytes"))
	sum := sha256.Sum256(append([]byte("ed-key-bytes"), []byte("ml-key-bytes")...))
	want := ""
	hexed := hex.EncodeToString(sum[:])
	for i := 0; i < len(hexed); i += 4 {
		if want != "" {
			want += " "
		}
		want += hexed[i : i+4]
	}
	if got := TeeSigningKeyFingerprint(ed, ml); got != want {
		t.Fatalf("fingerprint = %q, want %q", got, want)
	}
}
