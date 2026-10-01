package e2ee

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
	cachedTeeEnclaveKeySet = nil
	return FetchTeeEnclaveKeySet()
}

func TestEnclaveKeyFetchRefusesSgxToNoneDowngrade(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
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

func TestEnclaveKeyFetchRefusesMrenclaveChange(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	first := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("first contact refused: %v", TeeEnclaveKeyRefusal())
	}

	restarted := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&restarted)
	if fetchFresh() == nil {
		t.Fatalf("an enclave restart under the pinned MRENCLAVE was refused: %v", TeeEnclaveKeyRefusal())
	}

	rebuilt := sgxTrusted(randKey(t, 32), "bb22")
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
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
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
	if !strings.Contains(TeeEnclaveKeyRefusal().Error(), teeSigningPksPath()) {
		t.Fatalf("refusal does not name the sidecar to delete: %v", TeeEnclaveKeyRefusal())
	}
}

func TestEnclaveKeyFetchAllowsNonSgxToSgxUpgrade(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
	var answer atomic.Pointer[attestationAnswer]
	first := nonSgx(randKey(t, 32))
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("non-SGX first contact refused: %v", TeeEnclaveKeyRefusal())
	}

	upgraded := sgxTrusted(randKey(t, 32), "aa11")
	answer.Store(&upgraded)
	if fetchFresh() == nil {
		t.Fatalf("a move to trusted SGX attestation was refused: %v", TeeEnclaveKeyRefusal())
	}

	back := nonSgx(randKey(t, 32))
	answer.Store(&back)
	if fetchFresh() != nil {
		t.Fatal("the posture did not ratchet after the SGX upgrade")
	}
}

func TestEnclaveKeyFetchPostureIsPerAccount(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
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
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
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
	if p := pinnedTeeAttestationPosture(); p == nil || p.Mrenclave != "aa11" {
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
	if p := pinnedTeeAttestationPosture(); p == nil || p.SealingPk != "x" {
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
			t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
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
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
	config.Get().Endpoint = "http://127.0.0.1:1"
	config.Get().APIKey = "unreachable-test"
	if fetchFresh() != nil {
		t.Fatal("an unreachable server produced a key set")
	}
	if err := TeeEnclaveKeyRefusal(); err != nil {
		t.Fatalf("refusal = %v, want nil so the caller says the scanner is not reachable", err)
	}
}

func TestUnknownPostureModeCountsAsUnpinned(t *testing.T) {
	withIsolatedPinStore(t)
	t.Cleanup(func() { cachedTeeEnclaveKeySet = nil })
	recordTeeAttestationPosture(teeAttestationPosture{Mode: "dcap", Mrenclave: "zz"})
	var answer atomic.Pointer[attestationAnswer]
	first := nonSgx(randKey(t, 32))
	answer.Store(&first)
	serveEnclaveKeys(t, &answer)
	if fetchFresh() == nil {
		t.Fatalf("a posture mode this build does not know bricked uploads instead of re-pinning: %v", TeeEnclaveKeyRefusal())
	}
	if p := pinnedTeeAttestationPosture(); p == nil || p.Mode != "none" {
		t.Fatalf("the unknown mode was not replaced by the observed posture: %+v", p)
	}
}
