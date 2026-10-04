package e2ee

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

type attestationAnswer struct {
	mode      string
	mrenclave string
	quote     string
	status    string
	x25519    []byte
	kyber     []byte
}

func sgxTrusted(x []byte, mr string) attestationAnswer {
	return attestationAnswer{mode: "epid", mrenclave: mr, quote: b64([]byte("quote")), status: "trusted", x25519: x, kyber: make([]byte, crypto.KyberPublicKeySize)}
}

func nonSgx(x []byte) attestationAnswer {
	return attestationAnswer{mode: "none", status: "unverified", x25519: x, kyber: make([]byte, crypto.KyberPublicKeySize)}
}

func serveEnclaveKeys(t *testing.T, answer *atomic.Pointer[attestationAnswer]) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		a := answer.Load()
		body := map[string]any{
			"success": true, "enabled": true, "available": true,
			"attestation": map[string]any{
				"enclave_public_key":       b64(a.x25519),
				"enclave_public_key_kyber": b64(a.kyber),
				"attestation_mode":         a.mode,
				"mrenclave":                a.mrenclave,
				"sgx_quote":                a.quote,
				"verification_status":      a.status,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "posture-test"
}

func fetchFresh() *crypto.PublicKeySet {
	defaultSession.teeEnclaveKeySet = nil
	return FetchTeeEnclaveKeySet(context.Background())
}

func TestEnclaveKeyFetchRefusesSgxToNoneDowngrade(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	x := randKey(t, 32)
	var answer atomic.Pointer[attestationAnswer]
	first := sgxTrusted(x, "aa11")
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)

	if fetchFresh() == nil {
		t.Fatalf("a trusted SGX attestation was refused on first contact: %v", TeeEnclaveKeyRefusal())
	}

	swapped := nonSgx(randKey(t, 32))
	answer.Store(&swapped)
	if fetchFresh() != nil {
		t.Fatal("after a trusted SGX contact the server claimed non-SGX and its fresh key was accepted")
	}
	if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_attestation_downgraded") {
		t.Fatalf("refusal reason = %v, want tee_attestation_downgraded", err)
	}
}

func TestEnclaveKeyFetchRefusesAnSgxKeySwapUnderThePinnedMrenclave(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	first := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("first contact refused: %v", TeeEnclaveKeyRefusal())
	}
	if fetchFresh() == nil {
		t.Fatalf("the pinned SGX key was refused on the second fetch: %v", TeeEnclaveKeyRefusal())
	}

	swapped := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&swapped)
	if fetchFresh() != nil {
		t.Fatal("a new sealing key under the pinned MRENCLAVE was accepted on the server's unverified word")
	}
	if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_enclave_pk_changed") {
		t.Fatalf("refusal reason = %v, want tee_enclave_pk_changed", err)
	}

	kyberSwapped := first
	kyberSwapped.kyber = randKey(t, crypto.KyberPublicKeySize)
	answer.Store(&kyberSwapped)
	if fetchFresh() != nil {
		t.Fatal("a swapped ML-KEM half under the pinned X25519 key was accepted")
	}
}

func TestEnclaveKeyFetchRefusesMrenclaveChange(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	first := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("first contact refused: %v", TeeEnclaveKeyRefusal())
	}

	rebuilt := first
	rebuilt.mrenclave = "bb22"
	answer.Store(&rebuilt)
	if fetchFresh() != nil {
		t.Fatal("a different MRENCLAVE was accepted without operator action")
	}
	if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_mrenclave_changed") {
		t.Fatalf("refusal reason = %v, want tee_mrenclave_changed", err)
	}
}

func TestEnclaveKeyFetchPinsNonSgxSealingKey(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	x := randKey(t, 32)
	var answer atomic.Pointer[attestationAnswer]
	first := nonSgx(x)
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("non-SGX first contact refused: %v", TeeEnclaveKeyRefusal())
	}
	if fetchFresh() == nil {
		t.Fatalf("the same non-SGX key was refused on the second fetch: %v", TeeEnclaveKeyRefusal())
	}

	swapped := nonSgx(randKey(t, 32))
	answer.Store(&swapped)
	if fetchFresh() != nil {
		t.Fatal("a swapped non-SGX sealing key was accepted")
	}
	if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_enclave_pk_changed") {
		t.Fatalf("refusal reason = %v, want tee_enclave_pk_changed", err)
	}
	if !strings.Contains(TeeEnclaveKeyRefusal().Error(), teeSigningPins.path()) {
		t.Fatalf("refusal does not name the sidecar to delete: %v", TeeEnclaveKeyRefusal())
	}
}

func TestEnclaveKeyFetchRefusesANoneToSgxFlip(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	x := randKey(t, 32)
	first := nonSgx(x)
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("non-SGX first contact refused: %v", TeeEnclaveKeyRefusal())
	}

	for _, claim := range []attestationAnswer{sgxTrusted(randKey(t, 32), "aa11"), sgxTrusted(x, "aa11")} {
		answer.Store(&claim)
		if fetchFresh() != nil {
			t.Fatal("a reply claiming a trusted SGX quote moved a non-SGX pin; this client never verifies quotes")
		}
		if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_attestation_mode_changed") {
			t.Fatalf("refusal reason = %v, want tee_attestation_mode_changed", err)
		}
	}
	if p := mustPinnedPosture(t); p == nil || p.Mode != "none" || p.SealingPk != b64(x) {
		t.Fatalf("a refused flip rewrote the pin: %+v", p)
	}
}

func TestEnclaveKeyFetchRefusesALegacySgxPinThatHoldsNoKeys(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	recordTeeAttestationPosture(teeAttestationPosture{Mode: "epid", Mrenclave: "aa11"})
	var answer atomic.Pointer[attestationAnswer]
	served := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&served)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() != nil {
		t.Fatal("an SGX pin with no sealing key accepted whatever key the server named")
	}
	if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_enclave_pk_changed") {
		t.Fatalf("refusal reason = %v, want tee_enclave_pk_changed", err)
	}
}

func TestEnclaveKeyFetchCompletesALegacyNonSgxPinWithItsMlKemHalf(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	x := randKey(t, 32)
	recordTeeAttestationPosture(teeAttestationPosture{Mode: "none", SealingPk: b64(x)})
	var answer atomic.Pointer[attestationAnswer]
	served := nonSgx(x)
	served.kyber = randKey(t, crypto.KyberPublicKeySize)
	answer.Store(&served)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("a legacy pin matching the X25519 half was refused: %v", TeeEnclaveKeyRefusal())
	}
	if p := mustPinnedPosture(t); p == nil || p.SealingPkKyber != b64(served.kyber) {
		t.Fatalf("the ML-KEM half was not added to the legacy pin: %+v", p)
	}

	swapped := served
	swapped.kyber = randKey(t, crypto.KyberPublicKeySize)
	answer.Store(&swapped)
	if fetchFresh() != nil {
		t.Fatal("once completed, the pin still accepted a new ML-KEM half")
	}
}

func TestEnclaveKeyFetchPostureIsPerAccount(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	first := nonSgx(randKey(t, 32))
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("first contact refused: %v", TeeEnclaveKeyRefusal())
	}

	setOwner(t, randKey(t, 32))
	other := nonSgx(randKey(t, 32))
	answer.Store(&other)
	if fetchFresh() == nil {
		t.Fatalf("a second account inherited the first account's sealing-key pin: %v", TeeEnclaveKeyRefusal())
	}
}

func TestEnclaveKeyFetchDoesNotPinOnMalformedKeys(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	bad := nonSgx(randKey(t, 32))
	bad.kyber = []byte("short")
	answer.Store(&bad)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() != nil {
		t.Fatal("a malformed kyber key was accepted")
	}

	good := nonSgx(randKey(t, 32))
	answer.Store(&good)
	if fetchFresh() == nil {
		t.Fatalf("a malformed first answer pinned its sealing key and refused the next: %v", TeeEnclaveKeyRefusal())
	}
}

func TestSigningPinAndPostureSurviveEachOthersWriter(t *testing.T) {
	withIsolatedPinStore(t)
	recordTeeAttestationPosture(teeAttestationPosture{Mode: "epid", Mrenclave: "aa11"})
	recordTeeSigningPk(b64([]byte("ed")), b64([]byte("ml")))
	if p := mustPinnedPosture(t); p == nil || p.Mrenclave != "aa11" {
		t.Fatalf("recording the signing pin dropped the posture: %+v", p)
	}
	recordTeeAttestationPosture(teeAttestationPosture{Mode: "none", SealingPk: "x"})
	if pin, ok := pinnedTeeSigningPk(); !ok || pin.Ed != b64([]byte("ed")) {
		t.Fatalf("recording the posture dropped the signing pin: %+v ok=%v", pin, ok)
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() { defer wg.Done(); recordTeeSigningPk(b64([]byte("ed")), b64([]byte("ml"))) }()
		go func() {
			defer wg.Done()
			recordTeeAttestationPosture(teeAttestationPosture{Mode: "none", SealingPk: "x"})
		}()
	}
	wg.Wait()
	if _, ok := pinnedTeeSigningPk(); !ok {
		t.Fatal("concurrent writers lost the signing pin")
	}
	if p := mustPinnedPosture(t); p == nil || p.SealingPk != "x" {
		t.Fatalf("concurrent writers lost the posture: %+v", p)
	}
}

func TestEnclaveKeyFetchNamesAMalformedKeyRatherThanReportingUnreachable(t *testing.T) {
	cases := []struct {
		name   string
		answer attestationAnswer
	}{
		{"short x25519", attestationAnswer{mode: "none", status: "unverified", x25519: randKey(t, 16), kyber: make([]byte, crypto.KyberPublicKeySize)}},
		{"short kyber", attestationAnswer{mode: "none", status: "unverified", x25519: randKey(t, 32), kyber: randKey(t, 8)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedPinStore(t)
			t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
			var answer atomic.Pointer[attestationAnswer]
			served := tc.answer
			answer.Store(&served)
			serveEnclaveKeys(t, &answer)

			if fetchFresh() != nil {
				t.Fatal("a key set that does not decode was accepted")
			}
			err := TeeEnclaveKeyRefusal()
			if err == nil {
				t.Fatal("a broken key from an answering server left no refusal, so callers print \"not reachable\"")
			}
			if !strings.Contains(err.Error(), "tee_enclave_key_malformed") {
				t.Fatalf("refusal = %v, want tee_enclave_key_malformed", err)
			}
		})
	}
}

func TestEnclaveKeyFetchLeavesNoRefusalWhenTheServerDoesNotAnswer(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	config.Get().Endpoint = "http://127.0.0.1:1"
	config.Get().APIKey = "unreachable-test"
	if fetchFresh() != nil {
		t.Fatal("an unreachable server produced a key set")
	}
	if err := TeeEnclaveKeyRefusal(); err != nil {
		t.Fatalf("refusal = %v, want nil so the caller says the scanner is not reachable", err)
	}
}

func mustPinnedPosture(t *testing.T) *teeAttestationPosture {
	t.Helper()
	p, err := pinnedTeeAttestationPosture()
	if err != nil {
		t.Fatalf("pin store unreadable: %v", err)
	}
	return p
}

func TestAnUnusablePinStoreFailsClosedAndIsNeverRewritten(t *testing.T) {
	x := randKey(t, 32)
	cases := []struct {
		name      string
		wholeFile bool
		store     func(owner string) string
	}{
		{"not JSON", true, func(string) string { return `{"v":1,"owners":` }},
		{"another format version", true, func(owner string) string {
			return fmt.Sprintf(`{"v":99,"owners":{%q:{"posture":{"mode":"none","sealing_pk":%q}}}}`, owner, b64(x))
		}},
		{"posture with no mode", false, func(owner string) string {
			return fmt.Sprintf(`{"v":%d,"owners":{%q:{"posture":{"sealing_pk":%q}}}}`, teeSigningPinVersion, owner, b64(x))
		}},
		{"posture with an unknown mode", false, func(owner string) string {
			return fmt.Sprintf(`{"v":%d,"owners":{%q:{"posture":{"mode":"dcap","mrenclave":"zz"}}}}`, teeSigningPinVersion, owner)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedPinStore(t)
			t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
			path := teeSigningPins.path()
			original := []byte(tc.store(signingPinOwner()))
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			var answer atomic.Pointer[attestationAnswer]
			served := nonSgx(x)
			answer.Store(&served)
			serveEnclaveKeys(t, &answer)

			if fetchFresh() != nil {
				t.Fatal("an unusable pin store was read as no pin and the served key was trusted")
			}
			if err := TeeEnclaveKeyRefusal(); err == nil || !strings.Contains(err.Error(), "tee_pin_store_unreadable") || !strings.Contains(err.Error(), "pc te repin") {
				t.Fatalf("refusal = %v, want tee_pin_store_unreadable naming pc te repin", err)
			}
			if tc.wholeFile {
				if _, err := checkTeeSigningPks(b64(randKey(t, 32)), b64(randKey(t, 32))); err == nil || !strings.Contains(err.Error(), "tee_pin_store_unreadable") {
					t.Fatalf("the download pin check read an unusable store as unpinned: %v", err)
				}
				recordTeeSigningPk(b64([]byte("ed")), b64([]byte("ml")))
				recordTeeAttestationPosture(teeAttestationPosture{Mode: "none", SealingPk: b64(x)})
			}
			if got, _ := os.ReadFile(path); !bytes.Equal(got, original) {
				t.Fatalf("the unusable store was rewritten:\n%s", got)
			}
		})
	}
}

func TestAMissingPinStoreStillPinsOnFirstContact(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	if _, err := os.Stat(teeSigningPins.path()); !os.IsNotExist(err) {
		t.Fatalf("fixture expected no pin store yet: %v", err)
	}
	var answer atomic.Pointer[attestationAnswer]
	served := nonSgx(randKey(t, 32))
	answer.Store(&served)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("first contact without a pin store was refused: %v", TeeEnclaveKeyRefusal())
	}
	if p := mustPinnedPosture(t); p == nil || p.SealingPk != b64(served.x25519) {
		t.Fatalf("first contact did not pin: %+v", p)
	}
}

func TestRepinSetsAnUnusablePinStoreAsideInsteadOfOverwritingIt(t *testing.T) {
	withIsolatedPinStore(t)
	path := teeSigningPins.path()
	original := []byte(`{"v":1,"owners":`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	x := randKey(t, 32)
	posture, err := postureFor(servedAttestation{Mode: "none", SealingPk: b64(x), SealingPkKyber: b64(make([]byte, crypto.KyberPublicKeySize))})
	if err != nil {
		t.Fatal(err)
	}
	offer := &TeeAttestationOffer{Ed25519: b64(randKey(t, crypto.Ed25519PKSize)), Mldsa: b64(randKey(t, crypto.Mldsa44PKSize)), posture: posture}
	if err := RepinTeeSigningPk(offer); err != nil {
		t.Fatalf("repin over an unusable store failed: %v", err)
	}
	if kept, err := os.ReadFile(path + ".unreadable"); err != nil || !bytes.Equal(kept, original) {
		t.Fatalf("the unusable store was not kept beside the new one: %q, %v", kept, err)
	}
	if p := mustPinnedPosture(t); p == nil || p.SealingPk != b64(x) {
		t.Fatalf("repin did not write the offered posture: %+v", p)
	}
}

func TestAdoptingTheMlKemHalfOfALegacyPinSaysSo(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { defaultSession.teeEnclaveKeySet = nil })
	var notices []string
	saved := teeNotice
	teeNotice = func(msg string) { notices = append(notices, msg) }
	t.Cleanup(func() { teeNotice = saved })
	x := randKey(t, 32)
	recordTeeAttestationPosture(teeAttestationPosture{Mode: "none", SealingPk: b64(x)})
	var answer atomic.Pointer[attestationAnswer]
	served := nonSgx(x)
	answer.Store(&served)
	serveEnclaveKeys(t, &answer)

	if fetchFresh() == nil {
		t.Fatalf("legacy pin refused: %v", TeeEnclaveKeyRefusal())
	}
	if len(notices) != 1 || !strings.Contains(notices[0], "post-quantum") || !strings.Contains(notices[0], "pc te repin") {
		t.Fatalf("notices = %q, want one line naming the post-quantum pin and pc te repin", notices)
	}
	if fetchFresh() == nil {
		t.Fatalf("the completed pin was refused: %v", TeeEnclaveKeyRefusal())
	}
	if len(notices) != 1 {
		t.Fatalf("the notice repeated once the pin held both halves: %q", notices)
	}
}
