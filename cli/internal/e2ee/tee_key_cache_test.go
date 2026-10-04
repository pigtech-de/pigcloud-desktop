package e2ee

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

type countingAttestation struct {
	calls   atomic.Int32
	answer  atomic.Pointer[attestationAnswer]
	refuse  atomic.Bool
	before  func(n int32, w http.ResponseWriter) bool
	delay   time.Duration
	entered chan struct{}
	gate    chan struct{}
}

func fastAttestationRetries(t *testing.T) {
	t.Helper()
	saved := api.TeeAttestationRetryDelays
	api.TeeAttestationRetryDelays = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
	t.Cleanup(func() { api.TeeAttestationRetryDelays = saved })
}

func serveCountingAttestation(t *testing.T, a *countingAttestation) {
	t.Helper()
	fastAttestationRetries(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("action") != "tee-attestation" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		n := a.calls.Add(1)
		if a.gate != nil {
			select {
			case a.entered <- struct{}{}:
			default:
			}
			<-a.gate
		}
		time.Sleep(a.delay)
		w.Header().Set("Content-Type", "application/json")
		if a.before != nil && a.before(n, w) {
			return
		}
		if a.refuse.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"success":false,"error":"api_key_verify_busy"}`)
			return
		}
		ans := a.answer.Load()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true, "enabled": true, "available": true,
			"attestation": map[string]any{
				"enclave_public_key":       b64(ans.x25519),
				"enclave_public_key_kyber": b64(ans.kyber),
				"attestation_mode":         ans.mode,
				"mrenclave":                ans.mrenclave,
				"sgx_quote":                ans.quote,
				"verification_status":      ans.status,
			},
		})
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "cache-test"
}

func staleSealRefusal() error {
	return fmt.Errorf("upload: %w", &api.RequestError{
		Kind:       api.KindTransient,
		StatusCode: http.StatusServiceUnavailable,
		Err:        &api.APIError{Code: api.StaleTeeSealCode, Message: "The security scanner is unavailable."},
	})
}

func primedSession(t *testing.T, a *countingAttestation, first attestationAnswer) (*Session, *crypto.PublicKeySet) {
	t.Helper()
	a.answer.Store(&first)
	serveCountingAttestation(t, a)
	s := NewSession(nil, nil)
	set := s.FetchTeeEnclaveKeySet(context.Background())
	if set == nil {
		t.Fatalf("first contact refused: %v", s.TeeEnclaveKeyRefusal())
	}
	return s, set
}

func TestEnclaveKeyFetchWaitsOutA503AndNeverCallsItMalformed(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	good := nonSgx(randKey(t, 32))
	a.answer.Store(&good)
	a.before = func(n int32, w http.ResponseWriter) bool {
		if n > 1 {
			return false
		}
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"success":false,"error":"api_key_verify_busy"}`)
		return true
	}
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	if set := s.FetchTeeEnclaveKeySet(context.Background()); set == nil {
		t.Fatalf("one verify-busy 503 lost the key set; refusal: %v", s.TeeEnclaveKeyRefusal())
	}
	if got := a.calls.Load(); got != 2 {
		t.Errorf("attestation requests = %d, want the 503 plus one retry", got)
	}
}

func TestEnclaveKeyFetchUnderAPersistent503IsUnreachableNotMalformed(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	a.refuse.Store(true)
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	if set := s.FetchTeeEnclaveKeySet(context.Background()); set != nil {
		t.Fatal("a 503 body produced a sealing key")
	}
	if refusal := s.TeeEnclaveKeyRefusal(); refusal != nil {
		t.Fatalf("a 503 was reported as a refused answer %q; it must read as unreachable so the upload is retried", refusal)
	}
	if s.TeeScannerDisabledByServer() {
		t.Fatal("a 503 was read as the server saying it runs no scanner")
	}
}

func TestEnclaveKeyFetchRefusesAMalformedKeyServedAt200(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	short := nonSgx(randKey(t, 16))
	a.answer.Store(&short)
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	if set := s.FetchTeeEnclaveKeySet(context.Background()); set != nil {
		t.Fatal("a 16-byte X25519 key was accepted")
	}
	refusal := s.TeeEnclaveKeyRefusal()
	if refusal == nil || !strings.Contains(refusal.Error(), "tee_enclave_key_malformed") {
		t.Fatalf("refusal = %v, want tee_enclave_key_malformed", refusal)
	}
	if got := a.calls.Load(); got != 1 {
		t.Errorf("attestation requests = %d, a malformed 200 is not transient and must not be retried", got)
	}
}

func TestParallelUploadsFetchTheAttestationOnce(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{delay: 50 * time.Millisecond}
	good := nonSgx(randKey(t, 32))
	a.answer.Store(&good)
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	const workers = 16
	sets := make([]*crypto.PublicKeySet, workers)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Go(func() { sets[i] = s.FetchTeeEnclaveKeySet(context.Background()) })
	}
	wg.Wait()
	for range workers {
		wg.Go(func() { _ = s.FetchTeeEnclaveKeySet(context.Background()) })
	}
	wg.Wait()

	if got := a.calls.Load(); got != 1 {
		t.Fatalf("attestation requests = %d for %d parallel uploads, want 1", got, 2*workers)
	}
	for i, set := range sets {
		if set == nil || !sameTeeKeySet(set, sets[0]) {
			t.Fatalf("worker %d got %v, want the one shared key set", i, set)
		}
	}
}

func TestWaitersOnAFailingProbeShareItsOneRetryLadder(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{delay: 20 * time.Millisecond}
	a.refuse.Store(true)
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	const workers = 16
	var got atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			if s.FetchTeeEnclaveKeySet(context.Background()) != nil {
				got.Add(1)
			}
		})
	}
	wg.Wait()

	if got.Load() != 0 {
		t.Fatalf("%d waiters got a key set from a probe that only saw 503s", got.Load())
	}
	if n, want := a.calls.Load(), int32(len(api.TeeAttestationRetryDelays)+1); n != want {
		t.Fatalf("attestation requests = %d, want the leader's %d and nothing from %d waiters", n, want, workers-1)
	}
	if s.TeeEnclaveKeyRefusal() != nil {
		t.Fatalf("a failed probe left a refusal: %v", s.TeeEnclaveKeyRefusal())
	}
}

func TestARepinDuringAProbeDiscardsItsAnswer(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{entered: make(chan struct{}, 1), gate: make(chan struct{})}
	good := nonSgx(randKey(t, 32))
	a.answer.Store(&good)
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	leader := make(chan *crypto.PublicKeySet, 1)
	go func() { leader <- s.FetchTeeEnclaveKeySet(context.Background()) }()
	<-a.entered
	s.forgetTeeAttestationMemos()
	close(a.gate)

	if set := <-leader; set != nil {
		t.Fatal("a probe that started before the repin handed out its answer")
	}
	s.mu.Lock()
	cached := s.teeEnclaveKeySet
	s.mu.Unlock()
	if cached != nil {
		t.Fatal("a probe that started before the repin wrote its answer into the cache")
	}
	if s.FetchTeeEnclaveKeySet(context.Background()) == nil {
		t.Fatalf("the fetch after the repin was refused: %v", s.TeeEnclaveKeyRefusal())
	}
	if got := a.calls.Load(); got != 2 {
		t.Fatalf("attestation requests = %d, want the discarded probe plus one fresh one", got)
	}
}

func TestAWaiterLeavesWhenItsContextEnds(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{entered: make(chan struct{}, 1), gate: make(chan struct{})}
	good := nonSgx(randKey(t, 32))
	a.answer.Store(&good)
	serveCountingAttestation(t, a)

	s := NewSession(nil, nil)
	leaderDone := make(chan struct{})
	go func() {
		defer close(leaderDone)
		_ = s.FetchTeeEnclaveKeySet(context.Background())
	}()
	t.Cleanup(func() {
		close(a.gate)
		<-leaderDone
	})
	<-a.entered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan *crypto.PublicKeySet, 1)
	go func() { done <- s.FetchTeeEnclaveKeySet(ctx) }()
	select {
	case set := <-done:
		if set != nil {
			t.Fatal("a cancelled waiter came back with a key set")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cancelled waiter stayed blocked behind the leader's probe")
	}
}

func TestStaleRefetchUnderANonePinRefusesAChangedKeyAndNeverReseals(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{delay: 20 * time.Millisecond}
	s, sealedTo := primedSession(t, a, nonSgx(randKey(t, 32)))

	attacker := nonSgx(randKey(t, 32))
	a.answer.Store(&attacker)
	const workers = 8
	var resealed, refused atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			stale, err := s.TeeSealWentStale(context.Background(), staleSealRefusal(), sealedTo)
			if stale {
				resealed.Add(1)
			}
			if err != nil && strings.Contains(err.Error(), "tee_enclave_pk_changed") {
				refused.Add(1)
			}
		})
	}
	wg.Wait()

	if resealed.Load() != 0 {
		t.Fatalf("%d workers were told to reseal to a key the account never pinned", resealed.Load())
	}
	if refused.Load() != workers {
		t.Fatalf("%d of %d workers failed closed with tee_enclave_pk_changed", refused.Load(), workers)
	}
	if got := a.calls.Load(); got != 2 {
		t.Fatalf("attestation requests = %d, want exactly one refetch for %d stale refusals", got, workers)
	}
	if s.FetchTeeEnclaveKeySet(context.Background()) != nil {
		t.Fatal("the refused key reached the cache")
	}
}

func TestStaleRefetchUnderAnSgxPinRefusesARestartedKey(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	s, sealedTo := primedSession(t, a, sgxTrusted(randKey(t, 32), "aa11"))

	restarted := sgxTrusted(randKey(t, 32), "aa11")
	a.answer.Store(&restarted)
	stale, err := s.TeeSealWentStale(context.Background(), staleSealRefusal(), sealedTo)
	if stale || err == nil || !strings.Contains(err.Error(), "tee_enclave_pk_changed") {
		t.Fatalf("stale = %v, err = %v; want no reseal and tee_enclave_pk_changed", stale, err)
	}
}

func TestStaleRefetchResealsOnlyToAKeyTheAccountRepinned(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	s, sealedTo := primedSession(t, a, nonSgx(randKey(t, 32)))

	repinned := nonSgx(randKey(t, 32))
	posture, err := postureFor(servedAttestation{Mode: repinned.mode, Status: repinned.status, SealingPk: b64(repinned.x25519), SealingPkKyber: b64(repinned.kyber)})
	if err != nil {
		t.Fatal(err)
	}
	recordTeeAttestationPosture(posture)
	a.answer.Store(&repinned)

	stale, err := s.TeeSealWentStale(context.Background(), staleSealRefusal(), sealedTo)
	if !stale || err != nil {
		t.Fatalf("stale = %v, err = %v; a key the user repinned elsewhere should earn one reseal", stale, err)
	}
	fresh := s.FetchTeeEnclaveKeySet(context.Background())
	if !teeKeySetMatchesPin(fresh) {
		t.Fatal("the reseal target is not the pinned key")
	}
	if stale, err := s.TeeSealWentStale(context.Background(), staleSealRefusal(), fresh); stale || err != nil {
		t.Fatalf("a stale signal against the current pinned key asked for a reseal (%v, %v)", stale, err)
	}
	if got := a.calls.Load(); got != 2 {
		t.Fatalf("attestation requests = %d, want the first contact plus one refetch", got)
	}
}

func TestStaleSignalsProbeAtMostOncePerGapEvenWithAnEmptyCache(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	s, sealedTo := primedSession(t, a, nonSgx(randKey(t, 32)))

	busy := fmt.Errorf("upload: %w", &api.APIError{Code: "scanner_busy"})
	if stale, err := s.TeeSealWentStale(context.Background(), busy, sealedTo); stale || err != nil {
		t.Fatalf("a busy shed was read as a stale seal (%v, %v)", stale, err)
	}
	if got := a.calls.Load(); got != 1 {
		t.Fatalf("a busy shed refetched the attestation (%d requests)", got)
	}

	a.refuse.Store(true)
	for range 5 {
		if stale, err := s.TeeSealWentStale(context.Background(), staleSealRefusal(), sealedTo); stale || err != nil {
			t.Fatalf("an unanswered refetch asked for a reseal (%v, %v)", stale, err)
		}
	}
	if got, want := a.calls.Load(), int32(1+len(api.TeeAttestationRetryDelays)+1); got != want {
		t.Fatalf("attestation requests = %d, want %d: five stale signals inside one gap earn one probe", got, want)
	}
}

func TestAStaleSignalWithNoAccountKeysSaysSoInsteadOfClaimingAKeyChange(t *testing.T) {
	withIsolatedPinStore(t)
	a := &countingAttestation{}
	s, sealedTo := primedSession(t, a, nonSgx(randKey(t, 32)))
	config.Get().PublicKey = ""

	stale, err := s.TeeSealWentStale(context.Background(), staleSealRefusal(), sealedTo)
	if stale {
		t.Fatal("a refetch that no pin could check asked for a reseal")
	}
	if err == nil || !strings.Contains(err.Error(), "tee_pin_owner_unknown") {
		t.Fatalf("err = %v, want tee_pin_owner_unknown rather than a key-change claim", err)
	}
}
