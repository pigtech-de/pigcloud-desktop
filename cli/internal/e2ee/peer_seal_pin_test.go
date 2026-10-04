package e2ee

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pigcloud/internal/api"
	"pigcloud/internal/config"
	"pigcloud/internal/crypto"
)

type sealIdentity struct {
	kem      *crypto.PublicKeySet
	signPub  *crypto.SigningPublicKeySet
	signPriv *crypto.SigningPrivateKeySet
}

func newSealIdentity(t *testing.T) *sealIdentity {
	t.Helper()
	kem, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("hybrid keygen: %v", err)
	}
	signPub, signPriv := signingPair(t)
	return &sealIdentity{kem: kem, signPub: signPub, signPriv: signPriv}
}

func (i *sealIdentity) rotateKem(t *testing.T) *sealIdentity {
	t.Helper()
	kem, _, err := crypto.GenerateHybridKeyPair()
	if err != nil {
		t.Fatalf("hybrid keygen: %v", err)
	}
	return &sealIdentity{kem: kem, signPub: i.signPub, signPriv: i.signPriv}
}

func (i *sealIdentity) withBorrowedEd25519(t *testing.T, lender *sealIdentity) *sealIdentity {
	t.Helper()
	return &sealIdentity{
		kem: i.kem,
		signPub: &crypto.SigningPublicKeySet{
			Ed25519: lender.signPub.Ed25519,
			Mldsa:   i.signPub.Mldsa,
		},
		signPriv: &crypto.SigningPrivateKeySet{
			Ed25519: lender.signPriv.Ed25519,
			Mldsa:   i.signPriv.Mldsa,
		},
	}
}

func (i *sealIdentity) bundle() *PeerKeyBundle {
	return &PeerKeyBundle{
		X25519:  i.kem.X25519[:],
		Kyber:   i.kem.Kyber,
		Ed25519: i.signPub.Ed25519[:],
		Mldsa:   i.signPub.Mldsa,
	}
}

func (i *sealIdentity) signedBundle(t *testing.T) *PeerKeyBundle {
	t.Helper()
	b := i.bundle()
	b.BundleSig = sealBundleSig(t, b, i.signPriv)
	return b
}

func sealBundleSig(t *testing.T, b *PeerKeyBundle, priv *crypto.SigningPrivateKeySet) []byte {
	t.Helper()
	sigEd, sigMl, err := crypto.SignKeyBundle(&crypto.KeyBundle{
		X25519: b.X25519, Kyber: b.Kyber, Ed25519: b.Ed25519, Mldsa: b.Mldsa,
	}, priv)
	if err != nil {
		t.Fatalf("SignKeyBundle: %v", err)
	}
	blob, err := json.Marshal(keyBundleSigBlob{V: 1, SigEd: b64(sigEd), SigMl: b64(sigMl)})
	if err != nil {
		t.Fatalf("marshal bundle sig: %v", err)
	}
	return blob
}

func TestPeerSealPin(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T) (first, second *PeerKeyBundle)
		wantErr string
		wantPin string
	}{
		{
			name: "first seal pins the served key",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				return nil, newSealIdentity(t).signedBundle(t)
			},
			wantPin: "second",
		},
		{
			name: "unchanged key seals again",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				b := newSealIdentity(t).signedBundle(t)
				return b, b
			},
			wantPin: "second",
		},
		{
			name: "rotation signed by the pinned signing key is accepted",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				alice := newSealIdentity(t)
				return alice.signedBundle(t), alice.rotateKem(t).signedBundle(t)
			},
			wantPin: "second",
		},
		{
			name: "changed key with no bundle signature is refused",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				alice := newSealIdentity(t)
				return alice.signedBundle(t), alice.rotateKem(t).bundle()
			},
			wantErr: "peer_seal_pk_changed",
			wantPin: "first",
		},
		{
			name: "changed key signed by another identity is refused",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				return newSealIdentity(t).signedBundle(t), newSealIdentity(t).signedBundle(t)
			},
			wantErr: "peer_seal_pk_changed",
			wantPin: "first",
		},
		{
			name: "changed key under the pinned ed25519 but a swapped ml-dsa key is refused",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				alice := newSealIdentity(t)
				forger := newSealIdentity(t).withBorrowedEd25519(t, alice)
				return alice.signedBundle(t), forger.signedBundle(t)
			},
			wantErr: "peer_seal_pk_changed",
			wantPin: "first",
		},
		{
			name: "rotation against a pin taken before the signing anchors is refused",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				alice := newSealIdentity(t)
				legacy := alice.bundle()
				legacy.Ed25519, legacy.Mldsa = nil, nil
				return legacy, alice.rotateKem(t).signedBundle(t)
			},
			wantErr: "peer_seal_pk_changed",
			wantPin: "first",
		},
		{
			name: "changed key carrying the old bundle signature is refused",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				alice := newSealIdentity(t)
				first := alice.signedBundle(t)
				second := alice.rotateKem(t).bundle()
				second.BundleSig = first.BundleSig
				return first, second
			},
			wantErr: "peer_seal_pk_changed",
			wantPin: "first",
		},
		{
			name: "first seal to an unusable key set is refused",
			build: func(t *testing.T) (*PeerKeyBundle, *PeerKeyBundle) {
				b := newSealIdentity(t).signedBundle(t)
				b.Kyber = b.Kyber[:len(b.Kyber)-1]
				return nil, b
			},
			wantErr: "peer_seal_pk_missing",
			wantPin: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedPinStore(t)
			first, second := tc.build(t)
			if first != nil {
				if err := PinPeerSealKey("alice", first); err != nil {
					t.Fatalf("pinning the first key failed: %v", err)
				}
			}

			err := PinPeerSealKey("alice", second)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("seal refused: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("a seal that should have been refused with %s was accepted", tc.wantErr)
			case tc.wantErr != "":
				if !IsSealPinFailure(err) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want a %s seal-pin failure, got %v", tc.wantErr, err)
				}
				if !strings.Contains(err.Error(), "alice") {
					t.Errorf("refusal does not name the peer: %v", err)
				}
				if tc.wantErr == "peer_seal_pk_changed" && !strings.Contains(err.Error(), "pc fr repin alice") {
					t.Errorf("refusal does not name the way to accept the change: %v", err)
				}
			}

			want := ""
			switch tc.wantPin {
			case "first":
				want = first.Fingerprint()
			case "second":
				want = second.Fingerprint()
			}
			if got := PinnedPeerSealFingerprint("alice"); got != want {
				t.Errorf("pinned fingerprint = %q, want %q", got, want)
			}
		})
	}
}

func TestPeerSealPinRefusalNamesBothFingerprints(t *testing.T) {
	withIsolatedPinStore(t)
	alice := newSealIdentity(t)
	first := alice.signedBundle(t)
	second := alice.rotateKem(t).bundle()

	if err := PinPeerSealKey("alice", first); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	err := PinPeerSealKey("alice", second)
	if err == nil {
		t.Fatal("an unattributable key change was accepted")
	}
	for _, want := range []string{FingerprintDisplay(first.Fingerprint()), FingerprintDisplay(second.Fingerprint())} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal does not print %q: %v", want, err)
		}
	}
}

func TestPeerSealRepinIsTheOnlyWayPastARefusal(t *testing.T) {
	withIsolatedPinStore(t)
	alice := newSealIdentity(t)
	first := alice.signedBundle(t)
	stranger := newSealIdentity(t).signedBundle(t)

	if err := PinPeerSealKey("alice", first); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	if err := PinPeerSealKey("alice", stranger); err == nil {
		t.Fatal("a substituted key sealed without a repin")
	}
	if err := RepinPeerSealKey("alice", stranger); err != nil {
		t.Fatalf("repin refused: %v", err)
	}
	if got := PinnedPeerSealFingerprint("alice"); got != stranger.Fingerprint() {
		t.Fatalf("repin did not move the pin: %q", got)
	}
	if err := PinPeerSealKey("alice", stranger); err != nil {
		t.Fatalf("seal after an explicit repin still refused: %v", err)
	}
	if err := RepinPeerSealKey("alice", stranger); err == nil {
		t.Error("repinning the already pinned key reported a change")
	}
}

func TestPeerSealPinRejectsHostileNames(t *testing.T) {
	withIsolatedPinStore(t)
	bundle := newSealIdentity(t).signedBundle(t)

	for _, name := range []string{"../../etc/passwd", "alice\n", strings.Repeat("a", maxPeerNameLen+1), ""} {
		if err := PinPeerSealKey(name, bundle); err == nil {
			t.Errorf("PinPeerSealKey(%q) accepted", name)
		}
		if err := RepinPeerSealKey(name, bundle); err == nil {
			t.Errorf("RepinPeerSealKey(%q) accepted", name)
		}
	}
	if n, err := PeerSealPinCount(); n != 0 || err != nil {
		t.Errorf("hostile names wrote %d sidecar entries (%v)", n, err)
	}
}

func TestPeerSealPinIsPerAccount(t *testing.T) {
	withIsolatedPinStore(t)
	bundle := newSealIdentity(t).signedBundle(t)
	if err := PinPeerSealKey("alice", bundle); err != nil {
		t.Fatalf("first pin: %v", err)
	}

	setOwner(t, randKey(t, 32))
	if got := PinnedPeerSealFingerprint("alice"); got != "" {
		t.Fatalf("a second account on this machine read the first one's pin: %q", got)
	}
	if n, err := PeerSealPinCount(); n != 0 || err != nil {
		t.Errorf("pin count = %d (%v) for a fresh account, want 0", n, err)
	}
}

func TestPeerSealPinRefusesOnAnUnreadableSidecar(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"not json", "garbage-not-json"},
		{"unknown version", `{"v":99,"owners":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withIsolatedPinStore(t)
			alice := newSealIdentity(t)
			if err := PinPeerSealKey("alice", alice.signedBundle(t)); err != nil {
				t.Fatalf("first pin: %v", err)
			}
			if err := os.WriteFile(peerSealPins.path(), []byte(tc.body), 0600); err != nil {
				t.Fatal(err)
			}

			err := PinPeerSealKey("bob", newSealIdentity(t).signedBundle(t))
			if err == nil {
				t.Fatal("an unreadable pin store TOFU-accepted a contact")
			}
			if !IsSealPinFailure(err) || !strings.Contains(err.Error(), "peer_seal_pk_store_unusable") {
				t.Fatalf("want a peer_seal_pk_store_unusable failure, got %v", err)
			}
			if !strings.Contains(err.Error(), peerSealPins.path()) {
				t.Errorf("refusal does not name the file to move aside: %v", err)
			}
			raw, readErr := os.ReadFile(peerSealPins.path())
			if readErr != nil || string(raw) != tc.body {
				t.Errorf("the unreadable store was overwritten: %q (%v)", raw, readErr)
			}
			if n, countErr := PeerSealPinCount(); countErr == nil {
				t.Errorf("pc doctor was told %d pins instead of a broken store", n)
			}
		})
	}
}

func TestPeerSealPinRefusesWhenTheStoreCannotBeWritten(t *testing.T) {
	withIsolatedPinStore(t)
	dir := filepath.Dir(peerSealPins.path())
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		t.Skipf("cannot make the config dir read-only here: %v", err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	if f, err := os.CreateTemp(dir, "writable-*"); err == nil {
		f.Close()
		os.Remove(f.Name())
		t.Skip("the config dir is still writable (running as root?)")
	}

	err := PinPeerSealKey("alice", newSealIdentity(t).signedBundle(t))
	if err == nil {
		t.Fatal("a share was sealed with no pin recorded")
	}
	if !IsSealPinFailure(err) || !strings.Contains(err.Error(), "peer_seal_pk_store_unusable") {
		t.Fatalf("want a peer_seal_pk_store_unusable failure, got %v", err)
	}
}

func TestPeerSigningIdentityCooldownIsPerPeer(t *testing.T) {
	withIsolatedPinStore(t)
	resetPeerBundleCache(t)

	alice, bob := newSealIdentity(t), newSealIdentity(t)
	served := map[string]*sealIdentity{"bob": bob}
	var asked []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		name := "alice"
		if strings.Contains(string(body), "bob") {
			name = "bob"
		}
		asked = append(asked, name)
		w.Header().Set("Content-Type", "application/json")
		id, ok := served[name]
		if !ok {
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprint(w, `{"success":false,"message":"no keys"}`)
			return
		}
		fmt.Fprintf(w, `{"success":true,"public_key":%q,"public_key_kyber":%q,"signing_public_key_ed25519":%q,"signing_public_key_mldsa":%q}`,
			b64(id.kem.X25519[:]), b64(id.kem.Kyber), b64(id.signPub.Ed25519[:]), b64(id.signPub.Mldsa))
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "seal-pin-test"

	ctx := context.Background()
	if _, err := PinShareRecipientSealKey(ctx, recipientRow("alice", alice)); err != nil {
		t.Fatalf("pinning the unreachable recipient failed: %v", err)
	}
	if _, err := PinShareRecipientSealKey(ctx, recipientRow("bob", bob)); err != nil {
		t.Fatalf("pinning the second recipient failed: %v", err)
	}

	if rec, _, _ := peerSealRecord("bob"); !rec.anchored() {
		t.Errorf("bob pinned without a signing anchor after alice's lookup failed: %+v", rec)
	}
	if len(asked) != 2 {
		t.Errorf("identity lookups = %v, want one per recipient", asked)
	}
}

func TestPinShareRecipientSealKeyUsesTheRowKeyNotTheFetchedOne(t *testing.T) {
	withIsolatedPinStore(t)
	resetPeerBundleCache(t)

	published := newSealIdentity(t)
	substituted := newSealIdentity(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"success":true,"public_key":%q,"public_key_kyber":%q,"signing_public_key_ed25519":%q,"signing_public_key_mldsa":%q,"key_bundle_sig":%q}`,
			b64(published.kem.X25519[:]), b64(published.kem.Kyber),
			b64(published.signPub.Ed25519[:]), b64(published.signPub.Mldsa),
			b64(published.signedBundle(t).BundleSig))
	}))
	t.Cleanup(srv.Close)
	config.Get().Endpoint = srv.URL
	config.Get().APIKey = "seal-pin-test"

	keys, err := PinShareRecipientSealKey(context.Background(), recipientRow("alice", substituted))
	if err != nil {
		t.Fatalf("first pin: %v", err)
	}
	if keys.X25519 != substituted.kem.X25519 {
		t.Fatal("the seal key came from the fetched bundle instead of the recipient row")
	}
	if got := PinnedPeerSealFingerprint("alice"); got != sealKeyFingerprint(substituted.kem.X25519[:], substituted.kem.Kyber) {
		t.Fatalf("the row's key was not the one pinned: %q", got)
	}

	mixed := published.rotateKem(t).bundle()
	mixed.BundleSig = published.signedBundle(t).BundleSig
	if err := PinPeerSealKey("alice", mixed); err == nil {
		t.Fatal("a bundle signature made over a different KEM key attributed the change")
	}
}

func TestPinPeerSealKeyFromPubkeyPinsWhatItReturns(t *testing.T) {
	withIsolatedPinStore(t)
	alice := newSealIdentity(t)
	signed := alice.signedBundle(t)

	keys, err := PinPeerSealKeyFromPubkey("alice", &api.E2EEPubkeyPayload{
		PublicKey:               b64(signed.X25519),
		PublicKeyKyber:          b64(signed.Kyber),
		SigningPublicKeyEd25519: b64(signed.Ed25519),
		SigningPublicKeyMldsa:   b64(signed.Mldsa),
		KeyBundleSig:            b64(signed.BundleSig),
	})
	if err != nil {
		t.Fatalf("first pin: %v", err)
	}
	if keys.X25519 != alice.kem.X25519 {
		t.Error("the returned seal key is not the payload's key")
	}
	if got := PinnedPeerSealFingerprint("alice"); got != signed.Fingerprint() {
		t.Fatalf("pinned %q, want the fingerprint of the key it returned", got)
	}
	rec, _, _ := peerSealRecord("alice")
	if !rec.anchored() {
		t.Error("the payload's signing halves were not recorded as the rotation anchor")
	}
}

func recipientRow(name string, id *sealIdentity) api.ShareRecipientWithKey {
	return api.ShareRecipientWithKey{
		Username:       name,
		PublicKey:      b64(id.kem.X25519[:]),
		PublicKeyKyber: b64(id.kem.Kyber),
	}
}

func resetPeerBundleCache(t *testing.T) {
	t.Helper()
	clear := func() {
		peerBundleMu.Lock()
		peerBundles = nil
		peerBundleNextTry = nil
		peerBundleMu.Unlock()
	}
	clear()
	t.Cleanup(clear)
}

func TestIsSealPinFailureClassification(t *testing.T) {
	pin := &SealPinError{Reason: "peer_seal_pk_changed", Peer: "alice", Detail: "x"}
	if !IsSealPinFailure(fmt.Errorf("share alice: %w", pin)) {
		t.Error("seal-pin failure lost through fmt.Errorf")
	}
	if IsSealPinFailure(errors.New("peer_seal_pk_changed")) {
		t.Error("a plain error with the same text was classified as a seal-pin failure")
	}
	if IsSealPinFailure(nil) {
		t.Error("nil classified as a seal-pin failure")
	}
}
